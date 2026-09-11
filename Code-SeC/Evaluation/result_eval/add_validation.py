import json
import os
import glob
import sys

def add_final_validation_field(json_file_path):
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            data = json.load(file)
        
        modified_count = 0
        for key, value in data.items():
            if isinstance(value, dict):
                if "final_validation" not in value:  
                    value["final_validation"] = True
                    modified_count += 1
        
       
        if modified_count > 0:
            with open(json_file_path, 'w', encoding='utf-8') as file:
                json.dump(data, file, indent=2, ensure_ascii=False)
            print(f"✓ {os.path.basename(json_file_path)}: add {modified_count} items")
        else:
            print(f"○ {os.path.basename(json_file_path)}:already exists, skip")
        
        return True
        
    except FileNotFoundError:
        print(f"✗ error: can't find {json_file_path}")
        return False
    except json.JSONDecodeError:
        print(f"✗ error: {json_file_path} not a valid json file")
        return False
    except Exception as e:
        print(f"✗ process {json_file_path} error: {e}")
        return False

def process_directory(directory_path):
    search_pattern = os.path.join(directory_path, "**", "*validated_secrets_db*")
    
    all_files = glob.glob(search_pattern, recursive=True)
    
    json_files = [f for f in all_files if os.path.isfile(f)]
    
    if not json_files:
        print(f"can't find in {directory_path} which contains 'validated_secrets_db' ")
        return
    
    print(f"found {len(json_files)} matched files: ")
    for file_path in json_files:
        print(f"  - {os.path.basename(file_path)}")
    
    print("\nbegin to process...")
    print("-" * 50)
    
    success_count = 0
    for file_path in json_files:
        if add_final_validation_field(file_path):
            success_count += 1
    
    print("-" * 50)
    print(f"finished: {success_count}/{len(json_files)} files")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python add_validation.py <directory_path>")
        sys.exit(1)

    directory_path = sys.argv[1]
    
    print(f"start to iterate: {directory_path}")
    process_directory(directory_path)
