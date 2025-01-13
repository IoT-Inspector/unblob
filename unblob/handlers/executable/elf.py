import io
import shutil
from pathlib import Path
from typing import Optional

import attrs
import lief
from structlog import get_logger

from unblob.extractor import carve_chunk_to_file
from unblob.file_utils import (
    Endian,
    File,
    convert_int8,
    convert_int32,
    convert_int64,
    iterate_patterns,
    round_up,
)
from unblob.models import HexString, StructHandler, ValidChunk

lief.logging.disable()

logger = get_logger()

KERNEL_MODULE_SIGNATURE_INFO_LEN = 12
KERNEL_MODULE_SIGNATURE_FOOTER = b"~Module signature appended~\n"

KERNEL_INIT_DATA_SECTION = ".init.data"


@attrs.define(repr=False)
class ElfChunk(ValidChunk):
    def extract(self, inpath: Path, outdir: Path):
        # ELF file extraction is special in that in the general case no new files are extracted, thus
        # when we want to clean up all carves to save place, carved ELF files would be deleted as well,
        # however we want to keep carved out ELF files, as they are the interesting stuff!
        elf = lief.ELF.parse(str(inpath))

        if elf is None:
            logger.error(
                "Trying to extract an invalid ELF file.", inpath=inpath, outdir=outdir
            )
            return

        is_kernel = (
            elf.header.file_type == lief.ELF.Header.FILE_TYPE.EXEC
            and elf.has_section(KERNEL_INIT_DATA_SECTION)
        )
        if is_kernel:
            with File.from_path(inpath) as file:
                extract_initramfs(elf, file, outdir)
        elif not self.is_whole_file:
            # make a copy, and let the carved chunk be deleted
            outdir.mkdir(parents=True, exist_ok=False)
            shutil.copy2(inpath, outdir / "carved.elf")
            # more work will be done, when outdir is picked up by processing,
            # and the ELF file is processed as a whole file.
            # As a performance side effect, ELF files will be searched for chunks twice.
            # Even though the second chunk search one is short-circuited,
            # because the ELF handler will recognize it as a whole file
            # other handlers might burn some cycles on the file as well.


def extract_initramfs(elf, file: File, outdir):
    """Extract the initramfs part, with a potentially 4 extra bytes.

    Due to alignment definition of initramfs the start-end offsets can not be exactly calculated,
    so the output could have a 4 extra bytes before or after the initramfs.
    """
    if not elf.has_section(KERNEL_INIT_DATA_SECTION):
        return

    init_data = elf.get_section(KERNEL_INIT_DATA_SECTION)

    if not init_data.size:
        return

    is_64bit = elf.header.identity_class == lief.ELF.Header.CLASS.ELF64
    endian = (
        Endian.LITTLE
        if elf.header.identity_data == lief.ELF.Header.ELF_DATA.LSB
        else Endian.BIG
    )

    init_data_end_offset = init_data.file_offset + init_data.size

    # initramfs size is at the end of the section either 64bit or 32bit depending on the platform
    # see usr/initramfs_data.S in the kernel
    # The size is padded to 8 bytes, see include/asm-generic/vmlinux.lds.h
    # The actual initramfs is right before the size
    if is_64bit:
        initramfs_size_offset = init_data.file_offset + init_data.size - 8
        initramfs_size = convert_int64(
            file[initramfs_size_offset:init_data_end_offset],
            endian=endian,
        )
    else:
        initramfs_size_offset = init_data.file_offset + init_data.size - 4
        initramfs_size = convert_int32(
            file[initramfs_size_offset:init_data_end_offset],
            endian=endian,
        )

    # initramfs start is aligned to 4 bytes, initramfs_size_offset is aligned to 8 bytes
    # this is unfortunate, as we do not know the start, only the padded end
    # unfortunately we have two valid values for the padding of the initramfs end:
    #   0 and 4, 1 and 5, 2 and 6, 3 and 7
    # let's calculate the offsets for the smaller padding values
    initramfs_start = initramfs_size_offset - round_up(initramfs_size, 4)
    initramfs_end = initramfs_start + initramfs_size
    padding = initramfs_size_offset - initramfs_end

    # initramfs can be turned off (https://www.linux.com/training-tutorials/kernel-newbie-corner-initrd-and-initramfs-whats/)
    # in which case the above calculations most probably end up with bogus chunk offsets
    if not (
        init_data.file_offset <= initramfs_start < initramfs_end <= init_data_end_offset
        and (bytes(padding) == file[initramfs_end:initramfs_size_offset])
    ):
        return

    # when bigger padding is also a possibility, include 4 more bytes from the beginning
    if (init_data.file_offset <= initramfs_start - 4) and (
        bytes(padding + 4) == file[initramfs_end - 4 : initramfs_size_offset]
    ):
        initramfs_start -= 4

    carve_chunk_to_file(
        outdir / "initramfs",
        file,
        ValidChunk(start_offset=initramfs_start, end_offset=initramfs_end),
    )


class _ELFBase(StructHandler):
    EXTRACTOR = None
    SECTION_HEADER_STRUCT = "elf_shdr_t"
    PROGRAM_HEADER_STRUCT = "elf_phdr_t"

    def is_valid_header(self, header) -> bool:
        # check that header fields have valid values
        try:
            lief.ELF.Header.FILE_TYPE(header.e_type)
            lief.ELF.ARCH(header.e_machine)
            lief.ELF.Header.VERSION(header.e_version)
        except ValueError:
            return False
        return True

    @staticmethod
    def get_endianness(file: File, start_offset: int) -> Endian:
        file.seek(start_offset + 5, io.SEEK_SET)
        e_ident_data = convert_int8(file.read(1), Endian.LITTLE)
        return Endian.LITTLE if e_ident_data == 0x1 else Endian.BIG

    def get_last_section_end(
        self, file: File, sections_start_offset: int, sections_num: int, endian
    ) -> int:
        last_section_end = 0
        file.seek(sections_start_offset)

        for _ in range(sections_num):
            section_header = self._struct_parser.parse(
                self.SECTION_HEADER_STRUCT, file, endian
            )

            try:
                if (
                    lief.ELF.Section.TYPE(section_header.sh_type)
                    == lief.ELF.Section.TYPE.NOBITS
                ):
                    continue
            except ValueError:
                continue

            section_end = section_header.sh_offset + section_header.sh_size
            last_section_end = max(section_end, last_section_end)

        return last_section_end

    def get_last_program_end(
        self, file: File, programs_start_offset: int, programs_num: int, endian
    ) -> int:
        last_program_end = 0
        file.seek(programs_start_offset)

        for _ in range(programs_num):
            program_header = self._struct_parser.parse(
                self.PROGRAM_HEADER_STRUCT, file, endian
            )

            program_end = program_header.p_offset + program_header.p_filesz
            last_program_end = max(program_end, last_program_end)

        return last_program_end

    def get_end_offset(self, file: File, start_offset: int, header, endian) -> int:
        # Usually the section header is the last, but in some cases the program headers are
        # put to the end of the file, and in some cases sections header and actual sections
        # can be also intermixed, so we need also to check the end of the last section and
        # also the last program segment.
        # We check which one is the last and use it as a file size.
        section_headers_end = header.e_shoff + (header.e_shnum * header.e_shentsize)
        program_headers_end = header.e_phoff + (header.e_phnum * header.e_phentsize)

        last_section_end = self.get_last_section_end(
            file, start_offset + header.e_shoff, header.e_shnum, endian
        )

        last_program_end = self.get_last_program_end(
            file, start_offset + header.e_phoff, header.e_phnum, endian
        )

        return start_offset + max(
            section_headers_end, program_headers_end, last_section_end, last_program_end
        )

    def get_signed_kernel_module_end_offset(self, file: File, end_offset: int) -> int:
        # signed kernel modules are ELF files followed by:
        #   - a PKCS7 signature
        #   - a module_signature structure
        #   - a custom footer value '~~Module signature appended~\n~'
        # we check if a valid kernel module signature is present after the ELF file
        # and returns an end_offset that includes that whole signature part.

        file.seek(end_offset, io.SEEK_SET)
        for footer_offset in iterate_patterns(file, KERNEL_MODULE_SIGNATURE_FOOTER):
            file.seek(
                footer_offset - KERNEL_MODULE_SIGNATURE_INFO_LEN,
                io.SEEK_SET,
            )
            module_signature = self._struct_parser.parse(
                "module_signature_t", file, Endian.BIG
            )
            logger.debug(
                "module_signature_t",
                module_signature=module_signature,
                _verbosity=3,
            )
            if (
                footer_offset
                == end_offset
                + module_signature.sig_len
                + KERNEL_MODULE_SIGNATURE_INFO_LEN
            ):
                end_offset = footer_offset + len(KERNEL_MODULE_SIGNATURE_FOOTER)

            # We stop at the first SIGNATURE FOOTER match
            break

        return end_offset

    def calculate_chunk(self, file: File, start_offset: int) -> Optional[ElfChunk]:
        endian = self.get_endianness(file, start_offset)
        file.seek(start_offset, io.SEEK_SET)
        header = self.parse_header(file, endian)
        if not self.is_valid_header(header):
            return None
        end_offset = self.get_end_offset(file, start_offset, header, endian)

        # kernel modules are always relocatable
        if header.e_type == lief.ELF.Header.FILE_TYPE.REL.value:
            end_offset = self.get_signed_kernel_module_end_offset(file, end_offset)

        # do a special extraction of ELF files with ElfChunk
        return ElfChunk(
            start_offset=start_offset,
            end_offset=end_offset,
        )


class ELF32Handler(_ELFBase):
    NAME = "elf32"

    PATTERNS = [
        HexString(
            """
            // uint32 e_ident_magic;
            7F 45 4C 46
            // e_ident_class must be 0x1 (32bit) or 0x2 (64bit)
            01
            // e_ident_data must be 0x1 (little-endian) or 0x2 (big-endian)
            (01 | 02)
            // e_ident_version must be 0x1.
            01
            """
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct elf_header_32 {
            uint32 e_ident_magic;
            uint8 e_ident_class;
            uint8 e_ident_data;
            uint8 e_ident_version;
            uint8 e_ident_osabi;
            uint8 e_ident_abi_version;
            uint8 e_ident_pad[7];
            uint16 e_type;
            uint16 e_machine;
            uint32 e_version;
            uint32 e_entry;
            uint32 e_phoff;
            uint32 e_shoff;
            uint32 e_flags;
            uint16 e_ehsize;
            uint16 e_phentsize;
            uint16 e_phnum;
            uint16 e_shentsize;
            uint16 e_shnum;
            uint16 e_shstrndx;
        } elf_header_32_t;

        typedef struct elf32_shdr {
               uint32   sh_name;
               uint32   sh_type;
               uint32   sh_flags;
               uint32   sh_addr;
               uint32   sh_offset;
               uint32   sh_size;
               uint32   sh_link;
               uint32   sh_info;
               uint32   sh_addralign;
               uint32   sh_entsize;
       } elf_shdr_t;

       typedef struct elf32_phdr {
               uint32  p_type;
               uint32  p_offset;
               uint32  p_vaddr;
               uint32  p_paddr;
               uint32  p_filesz;
               uint32  p_memsz;
               uint32  p_flags;
               uint32  p_align;
           } elf_phdr_t;

        typedef struct module_signature {
            uint8   algo;           /* Public-key crypto algorithm [0] */
            uint8   hash;           /* Digest algorithm [0] */
            uint8   id_type;        /* Key identifier type [PKEY_ID_PKCS7] */
            uint8   signer_len;     /* Length of signer's name [0] */
            uint8   key_id_len;     /* Length of key identifier [0] */
            uint8   __pad[3];
            uint32  sig_len;        /* Length of signature data */
        } module_signature_t;
    """
    HEADER_STRUCT = "elf_header_32_t"


class ELF64Handler(_ELFBase):
    NAME = "elf64"

    PATTERNS = [
        HexString(
            """
            // uint32 e_ident_magic;
            7F 45 4C 46
            // e_ident_class must be 0x1 (32bit) or 0x2 (64bit)
            02
            // e_ident_data must be 0x1 (little-endian) or 0x2 (big-endian)
            (01 | 02)
            // e_ident_version must be 0x1.
            01
            """
        )
    ]

    C_DEFINITIONS = r"""
        typedef struct elf_header_64 {
            uint32 e_ident_magic;
            uint8 e_ident_class;
            uint8 e_ident_data;
            uint8 e_ident_version;
            uint8 e_ident_osabi;
            uint8 e_ident_abi_version;
            uint8 e_ident_pad[7];
            uint16 e_type;
            uint16 e_machine;
            uint32 e_version;
            uint64 e_entry;
            uint64 e_phoff;
            uint64 e_shoff;
            uint32 e_flags;
            uint16 e_ehsize;
            uint16 e_phentsize;
            uint16 e_phnum;
            uint16 e_shentsize;
            uint16 e_shnum;
            uint16 e_shstrndx;
        } elf_header_64_t;

        typedef struct elf64_shdr {
               uint32   sh_name;
               uint32   sh_type;
               uint64   sh_flags;
               uint64   sh_addr;
               uint64   sh_offset;
               uint64   sh_size;
               uint32   sh_link;
               uint32   sh_info;
               uint64   sh_addralign;
               uint64   sh_entsize;
       } elf_shdr_t;

       typedef struct elf64_phdr {
               uint32   p_type;
               uint32   p_flags;
               uint64   p_offset;
               uint64   p_vaddr;
               uint64   p_paddr;
               uint64   p_filesz;
               uint64   p_memsz;
               uint64   p_align;
           } elf_phdr_t;

        typedef struct module_signature {
            uint8   algo;           /* Public-key crypto algorithm [0] */
            uint8   hash;           /* Digest algorithm [0] */
            uint8   id_type;        /* Key identifier type [PKEY_ID_PKCS7] */
            uint8   signer_len;     /* Length of signer's name [0] */
            uint8   key_id_len;     /* Length of key identifier [0] */
            uint8   __pad[3];
            uint32  sig_len;        /* Length of signature data */
        } module_signature_t;
    """
    HEADER_STRUCT = "elf_header_64_t"
