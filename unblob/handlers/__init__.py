from ..models import DirectoryHandlers, Handlers
from .archive import ar, arc, arj, cab, cpio, dmg, rar, sevenzip, stuffit, tar, zip
from .archive.dlink import encrpted_img, shrs
from .archive.engeniustech import engenius
from .archive.hp import bdl, ipkg
from .archive.instar import bneg, instar_hd
from .archive.netgear import chk, trx
from .archive.qnap import qnap_nas
from .archive.xiaomi import hdr
from .compression import (
    bzip2,
    compress,
    gzip,
    lz4,
    lzh,
    lzip,
    lzma,
    lzo,
    xz,
    zlib,
    zstd,
)
from .executable import elf
from .filesystem import (
    cramfs,
    extfs,
    fat,
    iso9660,
    jffs2,
    ntfs,
    romfs,
    squashfs,
    ubi,
    yaffs,
)
from .filesystem.android import sparse

BUILTIN_HANDLERS: Handlers = (
    cramfs.CramFSHandler,
    extfs.EXTHandler,
    fat.FATHandler,
    jffs2.JFFS2NewHandler,
    jffs2.JFFS2OldHandler,
    ntfs.NTFSHandler,
    romfs.RomFSFSHandler,
    squashfs.SquashFSv2Handler,
    squashfs.SquashFSv2NonStandardHandler,
    squashfs.SquashFSv3Handler,
    squashfs.SquashFSv3DDWRTHandler,
    squashfs.SquashFSv3BroadcomHandler,
    squashfs.SquashFSv3NSHandler,
    squashfs.SquashFSv4LEHandler,
    squashfs.SquashFSv4BEHandler,
    ubi.UBIHandler,
    ubi.UBIFSHandler,
    yaffs.YAFFSHandler,
    chk.NetgearCHKHandler,
    trx.NetgearTRXv1Handler,
    trx.NetgearTRXv2Handler,
    encrpted_img.EncrptedHandler,
    shrs.SHRSHandler,
    hdr.HDR1Handler,
    hdr.HDR2Handler,
    qnap_nas.QnapHandler,
    bneg.BNEGHandler,
    bdl.HPBDLHandler,
    instar_hd.InstarHDHandler,
    ipkg.HPIPKGHandler,
    sparse.SparseHandler,
    ar.ARHandler,
    arc.ARCHandler,
    arj.ARJHandler,
    cab.CABHandler,
    tar.TarHandler,
    cpio.PortableASCIIHandler,
    cpio.PortableASCIIWithCRCHandler,
    cpio.PortableOldASCIIHandler,
    cpio.BinaryHandler,
    sevenzip.SevenZipHandler,
    rar.RarHandler,
    zip.ZIPHandler,
    dmg.DMGHandler,
    iso9660.ISO9660FSHandler,
    stuffit.StuffItSITHandler,
    stuffit.StuffIt5Handler,
    bzip2.BZip2Handler,
    compress.UnixCompressHandler,
    gzip.GZIPHandler,
    lzh.LZHHandler,
    lzip.LZipHandler,
    lzo.LZOHandler,
    lzma.LZMAHandler,
    lz4.LegacyFrameHandler,
    lz4.SkippableFrameHandler,
    lz4.DefaultFrameHandler,
    xz.XZHandler,
    zstd.ZSTDHandler,
    elf.ELF32Handler,
    elf.ELF64Handler,
    zlib.ZlibHandler,
    engenius.EngeniusHandler,
)

BUILTIN_DIR_HANDLERS: DirectoryHandlers = (sevenzip.MultiVolumeSevenZipHandler,)
