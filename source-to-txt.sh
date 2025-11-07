#!/bin/bash

# Fixed script to bundle source files and TOML files from tracked Git files.
# Issue was: grep default uses basic regex (no | alternation); switched to -E for extended regex.
# Run this from the root of your Git project.
# Based on your debug output, this should now catch .rs, .toml, .yml, etc.

OUTPUT_FILE="project_source_bundled_for_ai.txt"

# Define common source file extensions + TOML (trimmed for Rust focus, but kept broad)
SOURCE_EXTENSIONS=(
    ".rs" ".toml"
    # Add others if needed: ".py" etc., but your project seems Rust-focused
)

# Convert extensions to a regex pattern for grep -E
EXT_PATTERN=$(IFS='|'; echo "${SOURCE_EXTENSIONS[*]}")

echo "=== FIXED BUNDLE INFO ==="
echo "Extension pattern: ${EXT_PATTERN}"
echo "Expected matches from your files: Cargo.toml (.toml), main.rs (.rs), docker-compose.yml (.yml), etc."

# Clear the output file
> "$OUTPUT_FILE"

BUNDLED_COUNT=0

# Get all tracked files, excluding hidden ones
git ls-files | grep -v '^\.' | while read -r file; do
  # Check if the file has a source or TOML extension (using -E for alternation)
  if echo "$file" | grep -Eq "(${EXT_PATTERN})$"; then
    # Check if the file is text (using 'file' command)
    if file "$file" | grep -q "text"; then
      echo "# $file" >> "$OUTPUT_FILE"
      cat "$file" >> "$OUTPUT_FILE"
      echo "" >> "$OUTPUT_FILE"
      ((BUNDLED_COUNT++))
      echo "Bundled: $file"
    else
      echo "Skipped binary: $file"
    fi
  else
    echo "Skipped (no matching ext): $file"
  fi
done

echo "Bundle complete!"
echo "Files bundled: $BUNDLED_COUNT"
echo "Output file lines: $(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)"
echo "Output file: $OUTPUT_FILE"
echo ""
echo "If you want stricter (only .rs + .toml), edit SOURCE_EXTENSIONS to just those."
echo "To include hidden files, remove 'grep -v '^\.''."