import os
from fuzzconfig import FuzzConfig
import nonrouting
import pytrellis
import fuzzloops

DEVICE = os.environ.get("TRELLIS_DEVICE", "LFE5U-25F")


def dsp_tiles_for(device):
    if device == "LFE5U-25F":
        r, c0 = 13, 4
    elif device in ("LFE5U-85F", "LFE5UM5G-85F"):
        r, c0 = 34, 58
    else:
        raise RuntimeError("Unsupported TRELLIS_DEVICE '{}' for this fuzzer".format(device))

    tiles = []
    for i in range(9):
        c = c0 + i
        tiles.append("MIB_R{}C{}:MIB_DSP{}".format(r, c, i))
        tiles.append("MIB_R{}C{}:MIB2_DSP{}".format(r, c, i))
    return tiles


dsp_tiles = dsp_tiles_for(DEVICE)

if DEVICE == "LFE5U-25F":
    loc3, loc7 = "ALU24_R13C7", "ALU24_R13C11"
elif DEVICE in ("LFE5U-85F", "LFE5UM5G-85F"):
    loc3, loc7 = "ALU24_R34C61", "ALU24_R34C65"
else:
    raise RuntimeError("Unsupported TRELLIS_DEVICE '{}' for this fuzzer".format(DEVICE))

jobs = [
    (loc3, "ALU24_3", FuzzConfig(job="ALU24_3", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
    (loc7, "ALU24_7", FuzzConfig(job="ALU24_7", family="ECP5", device=DEVICE, ncl="empty.ncl", tiles=dsp_tiles)),
]


def main():
    pytrellis.load_database("../../../database")

    def per_job(job):
        def get_substs(settings, mode="ALU24B"):
            if mode == "NONE":
                comment = "//"
            else:
                comment = ""
            return dict(loc=loc, mode=mode, settings=",".join(["{}={}".format(k, v) for k, v in settings.items()]),
                        comment=comment)

        loc, alu, cfg = job
        cfg.setup()
        empty_bitfile = cfg.build_design(cfg.ncl, {})
        cfg.ncl = "dspconfig.ncl"

        nonrouting.fuzz_enum_setting(cfg, "{}.MODE".format(alu), ["NONE", "ALU24B"],
                                     lambda x: get_substs(settings={}, mode=x), empty_bitfile, False)

        regs = ["OUTPUT", "OPCODE_0", "OPCODE_1", "INPUTCFB"]
        clks = ["NONE", "CLK0", "CLK1", "CLK2", "CLK3"]
        cens = ["CE0", "CE1", "CE2", "CE3"]
        rsts = ["RST0", "RST1", "RST2", "RST3"]
        for reg in regs:
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CLK".format(alu, reg), clks,
                                         lambda x: get_substs(settings={"REG_{}_CLK".format(reg): x}), empty_bitfile,
                                         False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_CE".format(alu, reg), cens,
                                         lambda x: get_substs(settings={"REG_{}_CE".format(reg): x}), empty_bitfile,
                                         False)
            nonrouting.fuzz_enum_setting(cfg, "{}.REG_{}_RST".format(alu, reg), rsts,
                                         lambda x: get_substs(settings={"REG_{}_RST".format(reg): x}), empty_bitfile,
                                         False)

        for clk in ["CLK0", "CLK1", "CLK2", "CLK3"]:
            nonrouting.fuzz_enum_setting(cfg, "{}.{}_DIV".format(alu, clk), ["ENABLED", "DISABLED"],
                                         lambda x: get_substs(settings={"{}_DIV".format(clk): x}), empty_bitfile, False)

        nonrouting.fuzz_enum_setting(cfg, "{}.GSR".format(alu), ["DISABLED", "ENABLED"],
                                     lambda x: get_substs(settings={"GSR": x}), empty_bitfile, False)
        nonrouting.fuzz_enum_setting(cfg, "{}.RESETMODE".format(alu), ["SYNC", "ASYNC"],
                                     lambda x: get_substs(settings={"RESETMODE": x}), empty_bitfile, False)

    fuzzloops.parallel_foreach(jobs, per_job)


if __name__ == "__main__":
    main()
