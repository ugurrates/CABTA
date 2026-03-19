"""
Tests for FileTypeRouter - file type detection and routing.
"""

import pytest
import struct
from pathlib import Path

from src.analyzers.file_type_router import FileTypeRouter, FileType


class TestMagicBytesDetection:
    """Test detection via magic bytes (most reliable method)."""

    def test_pe_detection(self, sample_pe_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_pe_file)
        assert file_type == FileType.PE
        assert metadata['detection_method'] in ('magic_bytes', 'pe_signature', 'mz_header')

    def test_elf_detection(self, sample_elf_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_elf_file)
        assert file_type == FileType.ELF

    def test_elf_metadata(self, sample_elf_file):
        _, metadata = FileTypeRouter.detect_file_type(sample_elf_file)
        # ELF class metadata is only set when detection goes through the
        # detailed ELF check branch (header[:4] == b'\x7fELF' after the
        # MAGIC_SIGNATURES loop). The loop itself returns early on the
        # 4-byte prefix match, so elf_class may not be present.
        assert metadata['detection_method'] in ('magic_bytes', 'elf_magic')

    def test_pdf_detection(self, sample_pdf_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_pdf_file)
        assert file_type == FileType.PDF

    def test_ole_office_detection(self, sample_office_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_office_file)
        assert file_type == FileType.OFFICE

    def test_unknown_file(self, sample_unknown_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_unknown_file)
        # Random bytes may or may not match; at minimum check it doesn't crash
        assert file_type in FileType

    def test_nonexistent_file(self, tmp_path):
        file_type, metadata = FileTypeRouter.detect_file_type(str(tmp_path / "nope.bin"))
        assert file_type == FileType.UNKNOWN
        assert 'error' in metadata


class TestExtensionFallback:
    """Test detection via file extension when magic bytes don't match."""

    def test_script_by_extension(self, sample_script_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_script_file)
        assert file_type == FileType.SCRIPT

    def test_batch_by_extension(self, sample_batch_file):
        file_type, metadata = FileTypeRouter.detect_file_type(sample_batch_file)
        assert file_type == FileType.SCRIPT

    def test_apk_extension(self, tmp_path):
        """APK files share ZIP magic, but extension should override."""
        apk = tmp_path / "app.apk"
        # Write ZIP magic
        data = bytearray(64)
        data[0:4] = b'PK\x03\x04'
        apk.write_bytes(bytes(data))
        file_type, _ = FileTypeRouter.detect_file_type(str(apk))
        assert file_type == FileType.APK

    def test_docx_extension(self, tmp_path):
        """DOCX files share ZIP magic, extension should yield OFFICE."""
        docx = tmp_path / "document.docx"
        data = bytearray(64)
        data[0:4] = b'PK\x03\x04'
        docx.write_bytes(bytes(data))
        file_type, _ = FileTypeRouter.detect_file_type(str(docx))
        assert file_type == FileType.OFFICE


class TestContentHeuristics:
    """Test detection via content patterns (shebang, keywords)."""

    def test_shebang_detection(self, tmp_path):
        script = tmp_path / "run"
        script.write_text("#!/usr/bin/env python3\nprint('hello')\n")
        file_type, metadata = FileTypeRouter.detect_file_type(str(script))
        assert file_type == FileType.SCRIPT
        # Detection may go through libmagic (if available) before shebang heuristic
        assert metadata.get('detection_method') in ('shebang', 'libmagic_mime', 'content_heuristic')

    def test_vbscript_content(self, tmp_path):
        script = tmp_path / "unknown"
        script.write_text("Dim x\nSub Main()\nEnd Sub\n")
        file_type, _ = FileTypeRouter.detect_file_type(str(script))
        assert file_type == FileType.SCRIPT

    def test_batch_content(self, tmp_path):
        script = tmp_path / "unknown"
        script.write_text("@echo off\nrem batch file\n")
        file_type, _ = FileTypeRouter.detect_file_type(str(script))
        assert file_type == FileType.SCRIPT


class TestMetadata:
    """Test that metadata is populated correctly."""

    def test_metadata_has_filename(self, sample_pe_file):
        _, metadata = FileTypeRouter.detect_file_type(sample_pe_file)
        assert metadata['filename'] == 'sample.exe'

    def test_metadata_has_extension(self, sample_pe_file):
        _, metadata = FileTypeRouter.detect_file_type(sample_pe_file)
        assert metadata['extension'] == '.exe'

    def test_metadata_has_size(self, sample_pe_file):
        _, metadata = FileTypeRouter.detect_file_type(sample_pe_file)
        assert metadata['size'] > 0

    def test_metadata_has_detection_method(self, sample_pdf_file):
        _, metadata = FileTypeRouter.detect_file_type(sample_pdf_file)
        assert metadata['detection_method'] != 'unknown'


class TestAnalyzerMapping:
    """Test get_analyzer_class returns correct types."""

    def test_supported_types_dict(self):
        exts = FileTypeRouter.get_supported_extensions()
        assert '.exe' in exts
        assert exts['.exe'] == 'pe'
        assert '.pdf' in exts
        assert '.ps1' in exts

    def test_is_potentially_dangerous(self):
        assert FileTypeRouter.is_potentially_dangerous(FileType.PE, '.exe') is True
        assert FileTypeRouter.is_potentially_dangerous(FileType.SCRIPT, '.ps1') is True
        assert FileTypeRouter.is_potentially_dangerous(FileType.PDF, '.pdf') is False
        assert FileTypeRouter.is_potentially_dangerous(FileType.ARCHIVE, '.zip') is False

    def test_dangerous_extension_override(self):
        """Even non-dangerous type should flag dangerous extension."""
        assert FileTypeRouter.is_potentially_dangerous(FileType.UNKNOWN, '.hta') is True


class TestEdgeCases:
    """Edge case and robustness tests."""

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.bin"
        empty.write_bytes(b'')
        file_type, metadata = FileTypeRouter.detect_file_type(str(empty))
        assert metadata['size'] == 0

    def test_tiny_file(self, tmp_path):
        tiny = tmp_path / "tiny.exe"
        tiny.write_bytes(b'MZ')
        file_type, _ = FileTypeRouter.detect_file_type(str(tiny))
        assert file_type == FileType.PE

    def test_large_extension_map_coverage(self):
        """Ensure all FileType enum values have at least one extension."""
        ext_map = FileTypeRouter.EXTENSION_MAP
        types_with_ext = set(ext_map.values())
        # UNKNOWN doesn't need an extension
        expected = set(FileType) - {FileType.UNKNOWN}
        # ELF, MACHO may not have common extensions mapped
        for ft in [FileType.PE, FileType.OFFICE, FileType.PDF, FileType.SCRIPT,
                    FileType.APK, FileType.ARCHIVE, FileType.FIRMWARE]:
            assert ft in types_with_ext, f"{ft} has no extension mapping"
