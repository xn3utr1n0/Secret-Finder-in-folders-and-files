
# Secret Keyword Scanner

A high-performance, multithreaded Python tool to **scan files and directories for hardcoded secrets** such as passwords, API keys, tokens, and credentials. Supports more than 1,000 predefined keywords as well as easy user extension.

---

## Features

- 🚀 Fast, multithreaded scanning of files and folders.
- 🔑 Built-in list of 1,000+ sensitive keywords (and easy to add your own).
- 🔎 Flags any keyword as a substring (not just whole words, e.g. will catch `api_keyname`, `mypasswordis`).
- 🖼️ Generates an HTML report with file path, line number, exact line, and the matched phrase.
- 👍 Easily extensible for new secret patterns or custom keywords.

---

## Directory Structure

.
├── secret_finder.py # Main scanner script
├── README.md # This documentation
└── secrets_report.html # (Created after you run the tool)



---

## Installation

Requires **Python 3.6+**. No additional libraries are needed.

---

## Usage

To scan a file or directory (`/path/to/codebase_or_file`):

python secret_finder.py /path/to/codebase_or_file



- The scan produces an `secrets_report.html` file in the working directory.
- Open this file in your web browser to view all results in a table.

---

## How to Add Your Own Keywords

**Option 1: Edit the Script**  
At the top of `secret_finder.py`, you’ll see a section like this:

SENSITIVE_KEYWORDS = [
"password", "api_key", "secret", "aws_secret_access_key", ... # (Many more)
]



**Simply add your new keywords to this list**.  
Example:

SENSITIVE_KEYWORDS = [
"password", "api_key", "secret",
"my_special_token", # <-- Add custom keyword(s) here!
]



**Option 2: Read from a File (advanced, suggested for large teams)**  
Replace the `SENSITIVE_KEYWORDS` definition with:

with open("my_keywords.txt", "r") as f:
SENSITIVE_KEYWORDS = [line.strip() for line in f if line.strip() and not line.lstrip().startswith('#')]



Now, edit `my_keywords.txt` to add/remove your custom keywords.

**Remember:**  
- The scanner will match **any occurrence (substring) of your keyword** in variable, key, or file content.

---

## Sample Output

After scanning, open `secrets_report.html` in your browser. Here’s what you’ll see:

| File Path                | Line # | Line Content              | Matched Phrase |
|--------------------------|--------|---------------------------|---------------|
| src/settings.py          |   25   | password = "hunter2"      | password      |
| frontend/app.js          |   110  | api_keyname = "something" | api_key       |
| config/main.yml          |   8    | aws_secret_access_key: ...| aws_secret_access_key |

---

## How It Works

- Compiles a regex made from all keywords (case-insensitive, substrings matched).
- Walks all files in the target folder recursively.
- Each file is scanned in parallel.
- On every line, matches are reported (with file, line number, snippet, and matched phrase).
- A full HTML report is generated at the end.

---

## Example: Adding New Keywords

Suppose you want to add `supersecure` and `customer_token`, modify your list as:

SENSITIVE_KEYWORDS = [
"password", "api_key", "secret",
"supersecure",
"customer_token",
...
]



Now, the scanner will flag any line containing those as substrings!

---

## Contributing

- Pull requests are welcome! If you have a useful custom keyword list, open a PR or issue.

---

## License

MIT (see LICENSE file for details)

---

## Further Reading

- [GitHub Markdown Syntax Guide][1]
- [Project Tree Example][2]

[1]: https://docs.github.com/github/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax
[2]: https://stackoverflow.com/questions/23989232/is-there-a-way-to-represent-a-directory-tree-in-a-github-readme-md
How to modify the Python code for user-extensible keywords:
Replace this section in your script:

python
# -- Big expanded sensitive keywords list
SENSITIVE_KEYWORDS = [
    'password', 'api_key', ... # etc.
]
with:

python
# Load from file if exists, otherwise use hardcoded
if os.path.exists("my_keywords.txt"):
    with open("my_keywords.txt", "r") as f:
        SENSITIVE_KEYWORDS = [line.strip() for line in f if line.strip() and not line.startswith("#")]
else:
    SENSITIVE_KEYWORDS = [
        'password', 'api_key', ... # etc.
    ]