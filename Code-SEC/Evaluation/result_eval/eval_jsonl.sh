#!/bin/bash

PREFIX_INPUT_FILE="${OUTPUT_FILE}"
PREFIX_OUTPUT_FILE="${OUTPUT_FILE%.*}_processed.jsonl"

PS_FILE="$PREFIX_OUTPUT_FILE"
RS_FILE="${PREFIX_OUTPUT_FILE%.*}_cleaned.jsonl"

# add validation to DB
# python add_validation.py

python prefix_jsonl.py "$PREFIX_INPUT_FILE" "$PREFIX_OUTPUT_FILE"
python filter_jsonl.py "$PS_FILE"
python RS_main.py "$RS_FILE"