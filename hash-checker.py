import hashlib
import os


def calculate_hash(file_path, algorithm):
    try:
        hash_func = hashlib.new(algorithm)

        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                hash_func.update(chunk)

        return hash_func.hexdigest()

    except PermissionError:
        return "Permission denied"

    except Exception as e:
        return f"Error: {e}"


def main():
    print("\n=== File Integrity & Hash Checker ===\n")

    file_path = input("Enter file path: ")

    if not os.path.exists(file_path):
    print("\n[-] File not found!")
    return

if os.path.isdir(file_path):
    print("\n[-] Error: Please provide a file path, not a directory.")
    return

    print("\nCalculating hashes...\n")

    algorithms = ["md5", "sha1", "sha256"]

    for algo in algorithms:
        print(f"{algo.upper()}:")
        print(calculate_hash(file_path, algo))
        print()


if __name__ == "__main__":
    main()
