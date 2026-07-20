#!/bin/bash
# ============================================================
# LaTeX Build Script
# ============================================================
# Usage: ./build.sh [main.tex]
# Default: Compiles main.tex
#
# This script:
# 1. Creates an output directory
# 2. Auto-detects .bib files and runs bibtex if found
# 3. Runs pdflatex 2-4 times (for TOC, references, citations)
# 4. Moves the final PDF to the current directory
#

# Get the main file name (default: main.tex)
MAIN_FILE="${1:-main.tex}"

# Output directory for build files
OUTPUT_DIR="output"

# Check if the main file exists
if [ ! -f "$MAIN_FILE" ]; then
    echo "Error: $MAIN_FILE not found!"
    echo "Usage: ./build.sh [main.tex]"
    exit 1
fi

# Detect .bib files in current directory
BIB_FILE=$(ls *.bib 2>/dev/null | head -1)

# Create output directory
mkdir -p "$OUTPUT_DIR"

echo "============================================================"
echo "Building $MAIN_FILE..."
if [ -n "$BIB_FILE" ]; then
    echo "Bibliography detected: $BIB_FILE"
fi
echo "============================================================"

# First pass: Generate .aux file
echo "Pass 1: Compiling..."
pdflatex -interaction=nonstopmode -output-directory="$OUTPUT_DIR" "$MAIN_FILE" > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "Error: Compilation failed on first pass."
    echo "Check $OUTPUT_DIR/${MAIN_FILE%.tex}.log for details."
    exit 1
fi

# If bibliography exists, run bibtex
if [ -n "$BIB_FILE" ]; then
    echo "Processing bibliography..."
    # Copy .bib file to output directory for bibtex
    cp "$BIB_FILE" "$OUTPUT_DIR/" 2>/dev/null
    
    # Run bibtex
    cd "$OUTPUT_DIR"
    bibtex "${MAIN_FILE%.tex}" > /dev/null 2>&1
    BIBTEX_EXIT=$?
    cd ..
    
    if [ $BIBTEX_EXIT -ne 0 ]; then
        echo "Warning: BibTeX processing had issues."
        echo "Check $OUTPUT_DIR/${MAIN_FILE%.tex}.blg for details."
        echo "Continuing with compilation..."
    fi
    
    # Second pass: Resolve citations
    echo "Pass 2: Resolving citations..."
    pdflatex -interaction=nonstopmode -output-directory="$OUTPUT_DIR" "$MAIN_FILE" > /dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo "Error: Compilation failed on second pass."
        echo "Check $OUTPUT_DIR/${MAIN_FILE%.tex}.log for details."
        exit 1
    fi
    
    # Third pass: Finalize cross-references
    echo "Pass 3: Finalizing..."
    pdflatex -interaction=nonstopmode -output-directory="$OUTPUT_DIR" "$MAIN_FILE" > /dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo "Error: Compilation failed on third pass."
        echo "Check $OUTPUT_DIR/${MAIN_FILE%.tex}.log for details."
        exit 1
    fi
else
    # No bibliography: standard 2-pass compilation
    echo "Pass 2: Finalizing..."
    pdflatex -interaction=nonstopmode -output-directory="$OUTPUT_DIR" "$MAIN_FILE" > /dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo "Error: Compilation failed on second pass."
        echo "Check $OUTPUT_DIR/${MAIN_FILE%.tex}.log for details."
        exit 1
    fi
fi

# Move PDF to current directory for convenience
PDF_NAME="${MAIN_FILE%.tex}.pdf"
mv "$OUTPUT_DIR/$PDF_NAME" . 2>/dev/null

echo "============================================================"
echo "Build complete!"
echo "Output: $PDF_NAME"
echo "============================================================"

# Optional: Open the PDF (uncomment if desired)
# xdg-open "$PDF_NAME" 2>/dev/null || open "$PDF_NAME" 2>/dev/null

exit 0
