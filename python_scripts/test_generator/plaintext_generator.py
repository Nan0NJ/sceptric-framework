import os
from faker import Faker

sizing = 1

def generate_text(size_mb):
    """Generates a large text string of the given size in MB or KB using Faker."""
    fake = Faker()

    if sizing == 1 :
        size_bytes = size_mb * 1024 * 1024 # for MB
    else:
        size_bytes = size_mb # for KB
    text = ""
    while len(text.encode('utf-8')) < size_bytes:
        text += fake.text(max_nb_chars=1000) + " "  # Append realistic text
    return text[:size_bytes]  # Trim to exact size


def save_to_files(folder, sizes_mb):
    """Generates text files of different sizes and saves them as separate .txt files."""
    os.makedirs(folder, exist_ok=True)  # Ensure directory exists

    for size in sizes_mb:
        if sizing == 1:
            filename = os.path.join(folder, f"plaintext_MB{size}.txt")
        else:
            filename = os.path.join(folder, f"plaintext_KB{size}.txt")
        with open(filename, "w", encoding="utf-8") as file:
            file.write(generate_text(size))
        print(f"✔ Generated and saved: {filename}")


if __name__ == "__main__":
    output_folder = "test_datasets"
    save_to_files(output_folder, sizes_mb=[10, 50, 100, 500])  # Sizes in MB or KB depending on sizing
    print("✅ Test dataset saved in separate text files!")
