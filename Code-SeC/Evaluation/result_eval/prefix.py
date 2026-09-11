import json
import sys
def process_json_file(input_file, output_file):
    """Process JSON file to prepend prefix to output """
    # try:
    #     # Read JSON file
    #     with open(input_file, 'r', encoding='utf-8') as f:
    #         json_data = json.load(f)
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        try:
            json_data = json.loads(content)
            if not isinstance(json_data, list):
                json_data = [json_data]
        except json.JSONDecodeError:
            # Handle multiple JSON objects
            json_data = []
            parts = content.split('},\n{')
            
            for i, part in enumerate(parts):
                try:
                    if i == 0:
                        if not part.endswith('}'):
                            part += '}'
                    elif i == len(parts) - 1:
                        if not part.startswith('{'):
                            part = '{' + part
                    else:
                        if not part.startswith('{'):
                            part = '{' + part
                        if not part.endswith('}'):
                            part += '}'
                    
                    obj = json.loads(part)
                    json_data.append(obj)
                except json.JSONDecodeError:
                    continue
            
        # Process each JSON object
        processed_data = []
        for item in json_data:
            prefix = item.get('prefix', '')
            output = item.get('output', '')
            
            # Skip concatenation if output starts with AIza
            if output.startswith(('AIza', 'sk_test_', 'https://hooks.slack.com/services/', 'AKID', 'LTAI')):
                processed_data.append(item)
                continue

            # Prepend prefix to output
            item['output'] = prefix + output
            processed_data.append(item)
        
        # Save processed JSON to new file
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(processed_data, f, indent=2, ensure_ascii=False)
        
        print(f"Processing completed, saved to {output_file}")
    
    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found")
    except json.JSONDecodeError:
        print(f"Error: Failed to parse JSON file {input_file}")
    except Exception as e:
        print(f"An error occurred during processing: {str(e)}")

def main():
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    process_json_file(input_file, output_file)

if __name__ == "__main__":
    main()
