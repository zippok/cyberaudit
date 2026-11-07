"""Sandbox Execution Drivers — Strategy pattern for isolated test execution."""
import abc
import ast
import os
import sys
import subprocess
import tempfile
import time
import shutil
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

logger = logging.getLogger("cyberaudit.core.sandbox_drivers")

@dataclass
class ResourceLimits:
    """Resource constraints for sandbox execution.
    
    Provides stack-aware dynamic limits to prevent OOMKilled errors in memory-heavy
    runtimes (V8/Node.js, JVM/Gradle/Maven) while enforcing bounded blast radius.
    """
    memory_mb: int = 512
    cpu_fraction: float = 0.5
    timeout_seconds: int = 30
    max_processes: int = 64
    max_file_size_bytes: int = 10_485_760  # 10MB
    stack: str = "python"

    @classmethod
    def for_stack(
        cls,
        stack: str = "python",
        memory_mb: Optional[int] = None,
        cpu_fraction: Optional[float] = None,
        timeout_seconds: Optional[int] = None,
        max_processes: Optional[int] = None,
    ) -> "ResourceLimits":
        """Generate stack-aware resource limits.

        Profiles:
          - Java / JVM / Kotlin: 1536 MB, 1.0 CPU, 60s timeout
          - Node / TS / Jest: 1024 MB, 1.0 CPU, 45s timeout
          - Go / Rust: 1024 MB, 1.0 CPU, 30s timeout
          - Python: 512 MB, 0.5 CPU, 30s timeout
        """
        normalized = (stack or "python").lower().strip()

        if normalized in ("java", "jvm", "kotlin", "scala", "gradle", "maven"):
            base_mem, base_cpu, base_timeout = 1536, 1.0, 60
        elif normalized in ("node", "nodejs", "npm", "yarn", "typescript", "javascript", "jest", "v8"):
            base_mem, base_cpu, base_timeout = 1024, 1.0, 45
        elif normalized in ("go", "golang", "rust"):
            base_mem, base_cpu, base_timeout = 1024, 1.0, 30
        elif normalized in ("python", "pytest", "python3"):
            base_mem, base_cpu, base_timeout = 512, 0.5, 30
        else:
            base_mem, base_cpu, base_timeout = 512, 0.5, 30

        return cls(
            memory_mb=memory_mb if memory_mb is not None else base_mem,
            cpu_fraction=cpu_fraction if cpu_fraction is not None else base_cpu,
            timeout_seconds=timeout_seconds if timeout_seconds is not None else base_timeout,
            max_processes=max_processes if max_processes is not None else 64,
            stack=normalized,
        )

@dataclass 
class SandboxRunResult:
    """Result from an isolated sandbox test execution."""
    passed: bool
    exit_code: int
    output: str
    duration_ms: float
    driver_used: str = "unknown"
    error: Optional[str] = None
    
    def to_dict(self):
        return {"passed": self.passed, "exit_code": self.exit_code, "output": self.output,
                "duration_ms": self.duration_ms, "driver_used": self.driver_used, "error": self.error}


class SandboxDriver(abc.ABC):
    """Abstract base class for sandbox execution strategies."""
    
    @abc.abstractmethod
    def execute(self, test_code: str, base_dir: str, timeout: int = 15,
                resource_limits: Optional[ResourceLimits] = None) -> SandboxRunResult:
        ...
    
    @abc.abstractmethod
    def is_available(self) -> bool:
        ...
    
    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...


class LocalProcessDriver(SandboxDriver):
    """Executes tests in a local subprocess with tempdir isolation.
    Suitable for development. NOT suitable for untrusted code in production."""
    
    @property
    def name(self) -> str:
        return "local_process"
    
    def is_available(self) -> bool:
        return True  # Always available
    
    def execute(self, test_code: str, base_dir: str, timeout: int = 15,
                resource_limits: Optional[ResourceLimits] = None) -> SandboxRunResult:
        effective_timeout = timeout
        if resource_limits:
            effective_timeout = min(timeout, resource_limits.timeout_seconds)
        
        start = time.monotonic()
        try:
            with tempfile.TemporaryDirectory(prefix="cyberaudit_sandbox_") as tmpdir:
                test_file = os.path.join(tmpdir, "test_repro_ephemeral.py")
                with open(test_file, "w", encoding="utf-8") as f:
                    f.write(test_code)
                
                env = os.environ.copy()
                env["PYTHONPATH"] = os.path.abspath(tmpdir) + os.pathsep + os.path.abspath(base_dir) + os.pathsep + env.get("PYTHONPATH", "")
                env["CYBERAUDIT_SANDBOX"] = "1"
                
                cmd = [sys.executable, "-m", "pytest", test_file, "-v", "--tb=short"]
                proc = subprocess.run(
                    cmd, cwd=tmpdir, capture_output=True, text=True,
                    timeout=effective_timeout, env=env
                )
                elapsed = (time.monotonic() - start) * 1000
                return SandboxRunResult(
                    passed=(proc.returncode == 0),
                    exit_code=proc.returncode,
                    output=proc.stdout + proc.stderr,
                    duration_ms=round(elapsed, 2),
                    driver_used=self.name
                )
        except subprocess.TimeoutExpired:
            elapsed = (time.monotonic() - start) * 1000
            return SandboxRunResult(
                passed=False, exit_code=-1,
                output="", duration_ms=round(elapsed, 2),
                driver_used=self.name,
                error=f"Timeout after {effective_timeout}s"
            )
        except Exception as e:
            elapsed = (time.monotonic() - start) * 1000
            return SandboxRunResult(
                passed=False, exit_code=-2,
                output="", duration_ms=round(elapsed, 2),
                driver_used=self.name,
                error=str(e)
            )


class DockerEphemeralDriver(SandboxDriver):
    """Executes tests in ephemeral Docker containers with strict isolation.
    Production-grade: no network, memory limits, read-only filesystem.

    ── Docker-in-Docker (DinD) Security Warning ──────────────────────────────
    When the CI/CD runner is ITSELF a container (GitHub Actions, GitLab CI,
    Kubernetes pods), launching a child container requires access to the host
    Docker daemon via one of two mechanisms — both carry security implications:

    Option A — Shared Socket (``/var/run/docker.sock`` mount):
        Grants the runner container full root-equivalent access to the host.
        Any code executed inside the child container can escape to the host if
        the Docker daemon is not protected by user-namespace remapping.
        **Do NOT use in multi-tenant CI/CD environments.**

    Option B — Docker-in-Docker Sidecar (``--privileged`` DinD):
        Requires ``--privileged`` flag, which disables all seccomp/AppArmor
        profiles and is equivalent to running as root on the host kernel.
        **Avoid in production runners.**

    Recommended Alternatives for Containerized CI/CD:
        1. Use ``DryRunDriver`` (default) in containerized runners — validates
           code statically without launching child containers.
        2. Use GitHub Actions with ``runs-on: ubuntu-latest`` (bare metal/VM
           runners) where Docker is native, not nested.
        3. Replace Docker with **Kata Containers** or **gVisor (runsc)** —
           hardware-isolated microVMs that do not require socket access.
        4. Use **Firecracker microVMs** (AWS Lambda architecture) for fully
           isolated, sub-100ms sandboxes.

    The ``is_running_in_container()`` method detects containerized runners
    at startup. ``is_available()`` emits a WARNING log when DinD would be
    required (runner is containerized).
    """

    IMAGE_NAME = "cyberaudit-sandbox:latest"
    PRUNE_INTERVAL: int = 50    # Prune after every N sandbox runs
    _run_counter: int = 0       # Class-level run accumulator

    @staticmethod
    def is_running_in_container() -> bool:
        """Detect whether the current process is running inside a container.

        Checks three signals (in order of reliability):
          1. ``/.dockerenv`` file — present in all Docker containers.
          2. ``/proc/1/cgroup`` — contains 'docker' or 'kubepods' in Linux
             containers.
          3. ``KUBERNETES_SERVICE_HOST`` environment variable — set by the
             Kubernetes kubelet in all pod containers.

        Returns:
            True if likely running inside a Docker/Kubernetes container.
            False on Windows or native hosts (safe to use Docker driver).
        """
        # Signal 1: /.dockerenv marker file
        if os.path.isfile("/.dockerenv"):
            return True
        # Signal 2: /proc/1/cgroup content (Linux only)
        cgroup_path = "/proc/1/cgroup"
        if os.path.isfile(cgroup_path):
            try:
                with open(cgroup_path, "r") as f:
                    content = f.read().lower()
                if "docker" in content or "kubepods" in content or "containerd" in content:
                    return True
            except OSError:
                pass
        # Signal 3: Kubernetes environment variable
        if os.environ.get("KUBERNETES_SERVICE_HOST"):
            return True
        return False

    @classmethod
    def prune_stale_resources(cls, force: bool = False) -> bool:
        """Explicitly prune dangling images and volumes from the runner host.
        Can be invoked directly during teardown or CI post-steps."""
        try:
            p1 = subprocess.run(
                ["docker", "image", "prune", "--filter", "dangling=true", "-f"],
                capture_output=True, timeout=30
            )
            p2 = subprocess.run(
                ["docker", "volume", "prune", "-f"],
                capture_output=True, timeout=30
            )
            logger.info("Explicit Docker prune executed: images rc=%s, volumes rc=%s", p1.returncode, p2.returncode)
            return p1.returncode == 0 and p2.returncode == 0
        except Exception as exc:
            logger.debug("Explicit Docker prune failed (non-fatal): %s", exc)
            return False

    @classmethod
    def _maybe_prune_storage(cls) -> None:
        """Periodically prune dangling Docker images and anonymous volumes
        to prevent disk starvation on the CI runner host.

        Triggered every PRUNE_INTERVAL container executions. Non-fatal: any
        Docker error is logged at DEBUG level so a prune failure never aborts
        the audit pipeline.
        """
        cls._run_counter += 1
        if cls._run_counter % cls.PRUNE_INTERVAL != 0:
            return
        cls.prune_stale_resources()

    @property
    def name(self) -> str:
        return "docker_ephemeral"

    def is_available(self) -> bool:
        """Check whether the Docker daemon is reachable.

        Additionally warns if the current process is running inside a container
        (DinD scenario), because launching child containers would require
        mounting /var/run/docker.sock or running --privileged, both of which
        grant host-level privileges. In that case, prefer DryRunDriver.
        """
        if self.is_running_in_container():
            logger.warning(
                "DockerEphemeralDriver: Containerized runner detected (DinD scenario). "
                "Mounting /var/run/docker.sock grants host-root privileges. "
                "Consider using DryRunDriver or Kata Containers / gVisor microVMs instead."
            )
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    
    def _ensure_image(self) -> bool:
        """Build sandbox image if not present."""
        check = subprocess.run(
            ["docker", "image", "inspect", self.IMAGE_NAME],
            capture_output=True, text=True, timeout=10
        )
        if check.returncode == 0:
            return True
        
        # Build from inline Dockerfile
        dockerfile_content = (
            "FROM python:3.13-slim\\n"
            "RUN pip install --no-cache-dir pytest pyyaml\\n"
            "RUN useradd -m -s /bin/bash sandboxuser\\n"
            "USER sandboxuser\\n"
            "WORKDIR /workspace\\n"
        )
        try:
            with tempfile.TemporaryDirectory(prefix="cyberaudit_docker_build_") as build_dir:
                df_path = os.path.join(build_dir, "Dockerfile")
                with open(df_path, "w") as f:
                    f.write(dockerfile_content)
                result = subprocess.run(
                    ["docker", "build", "-t", self.IMAGE_NAME, "-f", df_path, build_dir],
                    capture_output=True, text=True, timeout=300
                )
                return result.returncode == 0
        except Exception as e:
            logger.warning("Failed to build Docker sandbox image: %s", e)
            return False
    
    def execute(self, test_code: str, base_dir: str, timeout: int = 15,
                resource_limits: Optional[ResourceLimits] = None) -> SandboxRunResult:
        limits = resource_limits or ResourceLimits()
        start = time.monotonic()
        
        if not self._ensure_image():
            elapsed = (time.monotonic() - start) * 1000
            return SandboxRunResult(
                passed=False, exit_code=-3, output="",
                duration_ms=round(elapsed, 2), driver_used=self.name,
                error="Failed to build/find Docker sandbox image"
            )
        
        container_name = f"cyberaudit_box_{int(time.time() * 1000)}"
        try:
            with tempfile.TemporaryDirectory(prefix="cyberaudit_docker_run_") as tmpdir:
                test_file = os.path.join(tmpdir, "test_repro_ephemeral.py")
                with open(test_file, "w", encoding="utf-8") as f:
                    f.write(test_code)
                
                # Convert Windows path for Docker mount if needed
                mount_path = tmpdir.replace("\\", "/")
                
                cmd = [
                    "docker", "run", "--rm",
                    f"--name={container_name}",
                    "--network", "none",
                    f"--memory={limits.memory_mb}m",
                    f"--cpus={limits.cpu_fraction}",
                    "--read-only",
                    "--tmpfs", "/tmp:size=32m,noexec,nosuid,nodev",
                    f"--pids-limit={limits.max_processes}",
                    f"--stop-timeout=3",
                    "-v", f"{mount_path}:/workspace:ro",
                    self.IMAGE_NAME,
                    "python", "-m", "pytest", "/workspace/test_repro_ephemeral.py",
                    "-v", "--tb=short",
                    f"--timeout={timeout}"
                ]
                
                container_timeout = timeout + 5  # Strict wall-clock buffer
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=container_timeout
                )
                elapsed = (time.monotonic() - start) * 1000
                self._maybe_prune_storage()
                return SandboxRunResult(
                    passed=(proc.returncode == 0),
                    exit_code=proc.returncode,
                    output=proc.stdout + proc.stderr,
                    duration_ms=round(elapsed, 2),
                    driver_used=self.name
                )
        except subprocess.TimeoutExpired:
            # Force kill the container by name to prevent zombie background workers
            try:
                subprocess.run(["docker", "rm", "-f", container_name],
                               capture_output=True, timeout=5)
            except Exception:
                pass
            elapsed = (time.monotonic() - start) * 1000
            return SandboxRunResult(
                passed=False, exit_code=-1, output="",
                duration_ms=round(elapsed, 2), driver_used=self.name,
                error=f"Hard wall-clock timeout after {timeout + 5}s (container {container_name} terminated)"
            )
        except Exception as e:
            try:
                subprocess.run(["docker", "rm", "-f", container_name],
                               capture_output=True, timeout=5)
            except Exception:
                pass
            elapsed = (time.monotonic() - start) * 1000
            return SandboxRunResult(
                passed=False, exit_code=-2, output="",
                duration_ms=round(elapsed, 2), driver_used=self.name,
                error=str(e)
            )


class DryRunDriver(SandboxDriver):
    """Validates test code syntax via AST parsing without executing.
    For CI environments without Docker where execution is not safe."""
    
    @property
    def name(self) -> str:
        return "dry_run"
    
    def is_available(self) -> bool:
        return True  # Always available
    
    def execute(self, test_code: str, base_dir: str, timeout: int = 15,
                resource_limits: Optional[ResourceLimits] = None) -> SandboxRunResult:
        start = time.monotonic()
        try:
            tree = ast.parse(test_code, filename="<sandbox_dryrun>")
            # Validate that at least one test function exists
            test_funcs = [n for n in ast.walk(tree)
                         if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
            
            elapsed = (time.monotonic() - start) * 1000
            if not test_funcs:
                return SandboxRunResult(
                    passed=False, exit_code=1,
                    output="DryRun: No test functions (test_*) found in code.",
                    duration_ms=round(elapsed, 2), driver_used=self.name,
                    error="No test functions found"
                )
            
            return SandboxRunResult(
                passed=True, exit_code=0,
                output=f"DryRun: AST validation passed. {len(test_funcs)} test function(s) found: {[f.name for f in test_funcs]}",
                duration_ms=round(elapsed, 2), driver_used=self.name
            )
        except SyntaxError as e:
            elapsed = (time.monotonic() - start) * 1000
            return SandboxRunResult(
                passed=False, exit_code=1,
                output=f"DryRun: Syntax error in test code: {e}",
                duration_ms=round(elapsed, 2), driver_used=self.name,
                error=f"SyntaxError: {e}"
            )


def auto_select_driver() -> SandboxDriver:
    """Auto-selects the best available sandbox driver.
    Priority: Docker > Local > DryRun"""
    docker = DockerEphemeralDriver()
    if docker.is_available():
        logger.info("Sandbox driver: Docker ephemeral (production isolation)")
        return docker
    
    local = LocalProcessDriver()
    logger.info("Sandbox driver: Local process (development mode — no Docker found)")
    return local
