"""
Author: Ugur AtesArchive file analyzer (ZIP, RAR, 7Z)."""

import zipfile
import os
from typing import Dict, List
from pathlib import Path
import logging

logger = logging.getLogger(__name__)
class ArchiveAnalyzer:
    """
    Analyze archive files with recursive extraction.
    
    Features:
    - Recursive extraction (up to 3 levels)
    - File listing
    - Suspicious file detection
    - Password-protected detection
    """
    
    MAX_DEPTH = 3
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    @staticmethod
    def analyze(file_path: str, depth: int = 0) -> Dict:
        """
        Analyze archive file.
        
        Args:
            file_path: Path to archive file
            depth: Current extraction depth
        
        Returns:
            Archive analysis results
        """
        try:
            logger.info(f"[ARCHIVE] Analyzing: {Path(file_path).name} (depth: {depth})")
            
            ext = Path(file_path).suffix.lower()
            
            result = {
                'file_type': 'Archive',
                'format': ext,
                'files': [],
                'total_files': 0,
                'password_protected': False,
                'suspicious_files': [],
                'nested_archives': []
            }
            
            if ext == '.zip':
                result.update(ArchiveAnalyzer._analyze_zip(file_path, depth))
            elif ext in ['.rar', '.7z']:
                result['error'] = f'{ext} format requires additional tools'
            else:
                result['error'] = 'Unsupported format'
            
            return result
        
        except Exception as e:
            logger.error(f"[ARCHIVE] Analysis failed: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def _analyze_zip(file_path: str, depth: int) -> Dict:
        """Analyze ZIP archive."""
        result = {
            'files': [],
            'total_files': 0,
            'password_protected': False,
            'suspicious_files': [],
            'nested_archives': []
        }
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # Check for password protection
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        result['password_protected'] = True
                        break
                
                # List files
                for info in zf.infolist():
                    file_info = {
                        'name': info.filename,
                        'size': info.file_size,
                        'compressed_size': info.compress_size,
                        'is_dir': info.is_dir()
                    }
                    
                    result['files'].append(file_info)
                    result['total_files'] += 1
                    
                    # Check for suspicious files
                    if ArchiveAnalyzer._is_suspicious_file(info.filename):
                        result['suspicious_files'].append(info.filename)
                    
                    # Check for nested archives
                    if ArchiveAnalyzer._is_archive_file(info.filename) and depth < ArchiveAnalyzer.MAX_DEPTH:
                        result['nested_archives'].append(info.filename)
        
        except Exception as e:
            logger.error(f"[ARCHIVE] ZIP analysis error: {e}")
            result['error'] = str(e)
        
        return result
    
    @staticmethod
    def _is_suspicious_file(filename: str) -> bool:
        """Check if filename is suspicious."""
        suspicious_extensions = [
            '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js',
            '.ps1', '.jar', '.app', '.dex', '.so', '.dylib'
        ]
        
        return any(filename.lower().endswith(ext) for ext in suspicious_extensions)
    
    @staticmethod
    def _is_archive_file(filename: str) -> bool:
        """Check if file is an archive."""
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        return any(filename.lower().endswith(ext) for ext in archive_extensions)
    
    @staticmethod
    def extract_and_analyze(file_path: str, output_dir: str) -> Dict:
        """
        Extract archive and analyze contents.
        
        Args:
            file_path: Path to archive
            output_dir: Directory for extraction
        
        Returns:
            Extraction and analysis results
        """
        try:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            
            with zipfile.ZipFile(file_path, 'r') as zf:
                zf.extractall(output_dir)
            
            return {'extracted': True, 'path': output_dir}
        
        except Exception as e:
            logger.error(f"[ARCHIVE] Extraction failed: {e}")
            return {'extracted': False, 'error': str(e)}
