"""Validate the installed upstream argument parser without loading a model/GPU."""
import argparse
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import tempfile
from unittest.mock import patch

unit = Path('/etc/systemd/system/ntrust-inference.service').read_text()
for line in unit.splitlines():
    if line.startswith('Environment='):
        for value in shlex.split(line.removeprefix('Environment=')):
            key, _, value = value.partition('=')
            os.environ[key] = value
runtime = Path('/run/ntrust-inference')
runtime.mkdir(mode=0o700, exist_ok=True)
with tempfile.TemporaryDirectory(dir=runtime) as tmp:
    # The chosen weight loader must work on the kernel without AIO/io_uring.
    import torch
    from safetensors.torch import load_file, save_file
    tensor = torch.arange(16, dtype=torch.float32)
    weights = str(Path(tmp, 'probe.safetensors'))
    save_file({'probe': tensor}, weights)
    assert torch.equal(load_file(weights)['probe'], tensor)
    print('PASS: actual CPU Safetensors save/load works; no GPU/model inference claimed')
    # Compile tiny test translation units; never execute a CUDA kernel.
    cuda = Path(tmp, 'probe.cu')
    cuda.write_text('#include <cuda_runtime.h>\n__global__ void probe() {}\n')
    subprocess.run(['/usr/local/cuda/bin/nvcc', '-arch=sm_90a', '--cubin', str(cuda), '-o', str(Path(tmp, 'probe.cubin'))], check=True)
    cpp = Path(tmp, 'probe.cpp')
    cpp.write_text('#include <Python.h>\nint probe() { return PY_MAJOR_VERSION; }\n')
    includes = shlex.split(subprocess.check_output(['/usr/bin/python3-config', '--includes'], text=True))
    subprocess.run(['g++', *includes, '-c', str(cpp), '-o', str(Path(tmp, 'probe.o'))], check=True)
    print('PASS: CUDA SM90a and Python-extension headers compile without a GPU')
    Path(tmp, 'api-key').write_text('a' * 64)
    os.environ['CREDENTIALS_DIRECTORY'] = tmp
    with patch('os.execv') as execute:
        runpy.run_path('/usr/local/lib/ntrust/inference-start', run_name='__main__')
    argv = execute.call_args.args[1]
    if 'sglang.launch_server' in argv:
        from sglang.srt.server_args import ServerArgs
        from sglang.srt.utils.server_args_config_parser import ConfigArgumentMerger
        parser = argparse.ArgumentParser()
        ServerArgs.add_cli_args(parser)
        options = ConfigArgumentMerger(parser).merge_config_with_args(argv[3:])
        args = parser.parse_args(options)
        assert args.api_key == 'a' * 64
        assert not args.log_requests and not args.enable_metrics and not args.enable_trace
        assert args.disable_radix_cache
    else:
        from vllm.entrypoints.launchers.cli_args import make_arg_parser
        from vllm.utils.argparse_utils import FlexibleArgumentParser
        # vLLM constructs DeviceConfig while building argparse defaults.
        # The build host has no GPU: mock only that type for this syntax test.
        # Production startup still uses real hardware detection and the GPU gate.
        from vllm.platforms import current_platform
        with patch.object(current_platform, 'device_type', 'cuda'):
            args = make_arg_parser(FlexibleArgumentParser()).parse_args(argv[3:] if argv[1] == '-m' else argv[2:])
        print('vLLM parser test used a mocked device type; this is not GPU execution')
        assert not args.enable_log_requests and args.disable_log_stats
        assert not args.enable_prefix_caching
        assert os.environ['VLLM_API_KEY'] == 'a' * 64
    assert args.host == '127.0.0.1' and args.port == 8080
    assert args.load_format == 'safetensors' and not args.trust_remote_code
print('PASS: installed upstream parser accepts the launcher and privacy options; no model/GPU executed')
