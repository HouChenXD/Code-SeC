#!/bin/bash

PREFIX_INPUT_FILE="${OUTPUT_FILE}"
PREFIX_OUTPUT_FILE="${OUTPUT_FILE%.*}_processed.json"

PS_FILE="$PREFIX_OUTPUT_FILE"
RS_FILE="${PREFIX_OUTPUT_FILE%.*}_cleaned.json"
# add validation to db
# python add_validation.py

python prefix.py "$PREFIX_INPUT_FILE" "$PREFIX_OUTPUT_FILE"
python filter.py "$PS_FILE"
python RS_main.py "$RS_FILE"