from adapters.source import SourceAdapter


class KernelSourceAdapter(SourceAdapter):
    markers = ("Makefile", "Kconfig", "include/linux")
