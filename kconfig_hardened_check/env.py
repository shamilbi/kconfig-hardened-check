# coding: utf-8


class Env:
    # debug_mode enables:
    #    - reporting about unknown kernel options in the config,
    #    - verbose printing of ComplexOptChecks (OR, AND).
    debug_mode = False

    # json_mode is for printing results in JSON format
    json_mode = False

    kernel_version = None

    # parsed config options
    kernel_config: dict = None

    kernel_arch: str = None
