"""
Python wrapper for `diamond.sh`
"""
from os import path
import os
import subprocess
import database


def run(device, source, no_trce=False, mapargs=None, backanno=False):
    """
    Run diamond.sh with a given device name and source Verilog file
    """
    env = os.environ.copy()
    if no_trce:
        env["NO_TRCE"] = "1"
    if backanno:
        env["BACKANNO"] = "1"
    if mapargs is not None:
        env["MAPARGS"] = mapargs
    dsh_path = path.join(database.get_trellis_root(), "diamond.sh")
    # On Windows (MINGW64), convert Windows paths to MSYS2/Git-bash paths
    # and use shell=True since subprocess.run(["bash", path]) fails on MINGW64
    import platform
    if platform.system() == "Windows":
        import re
        def to_msys_path(p):
            p = p.replace("\\", "/")
            m = re.match(r"^([A-Za-z]):/(.*)$", p)
            if m:
                return "/" + m.group(1).lower() + "/" + m.group(2)
            return p
        dsh_path = to_msys_path(dsh_path)
        source = to_msys_path(source)
        cmd = "bash {} {} {}".format(dsh_path, device, source)
        return subprocess.run(cmd, shell=True, env=env)
    else:
        return subprocess.run(["bash",dsh_path,device,source], env=env)

