import requests
import feedparser
import os
import time
from datetime import datetime

# A list of the RSS feeds and their corresponding output filenames.
FEEDS = [
    {
        "url": "https://www.bleepingcomputer.com/feed/",
        "filename": "BleepingComputer.html",
        "title": "Bleeping Computer"
    },
    {
        "url": "https://www.wired.com/feed/category/security/latest/rss",
        "filename": "WiredNews.html",
        "title": "Wired Security"
    },
    {
        "url": "http://newsrss.bbc.co.uk/rss/newsonline_uk_edition/technology/rss.xml",
        "filename": "BbcTech.html",
        "title": "BBC Technology"
    },
]

# Set a User-Agent header to mimic a web browser and avoid 403 Forbidden errors.
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

# The directory where the HTML files will be saved.
OUTPUT_DIRECTORY = "DashboardServer/templates/NewNews"

def fetch_and_generate_html(feed_data):
    """
    Fetches an RSS feed, parses it, and generates an HTML file
    with the specified styling and structure.
    
    Args:
        feed_data (dict): A dictionary containing the RSS feed URL,
                          output filename, and a descriptive title.
    """
    url = feed_data["url"]
    filename = feed_data["filename"]
    page_title = feed_data["title"]

    #print(f"Fetching feed from {url}...")
    try:
        # Use requests to get the feed content with a User-Agent and no SSL verification.
        response = requests.get(url, timeout=10, headers=HEADERS, verify=False)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

        # Parse the feed content using feedparser.
        feed = feedparser.parse(response.text)

        # Generate the HTML content for the news articles.
        articles_html = ""
        for entry in feed.entries:
            # Safely get the publication date.
            published_date = ""
            if hasattr(entry, 'published_parsed'):
                pub_date = datetime.fromtimestamp(time.mktime(entry.published_parsed))
                published_date = pub_date.strftime("%B %d, %Y")
            else:
                published_date = datetime.now().strftime("%B %d, %Y")

            # Create a clean summary or description.
            summary = ""
            if hasattr(entry, 'summary'):
                summary = entry.summary
            elif hasattr(entry, 'description'):
                summary = entry.description

            # Build the HTML for a single news card with the new styling.
            articles_html += f"""
            <div class="news-article">
                <h2><a href="{entry.link}" target="_blank">{entry.title}</a></h2>
                <p>{published_date}</p>
                <p>{summary}</p>
            </div>
            """
        
        # Generate the full HTML page with the new styling and articles.
        final_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title} News Feed</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #202522;
        }}
        .container {{
            max-width: 800px;
            margin: auto;
        }}
        h1 {{
            color: #cad4cb;
            text-align: center;
        }}
        .news-article {{
            background-color: #2f4132;
            border: 1px solid #00bf1d;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(53, 53, 53, 0.5);
        }}
        .news-article h2 {{
            margin-top: 0;
            font-size: 1.4em;
            color: #d0d8ce;
        }}
        .news-article h2 a {{
            text-decoration: none;
            color: inherit;
        }}
        .news-article h2 a:hover {{
            text-decoration: underline;
        }}
        .news-article p {{
            font-size: 1em;
            color: #a2a2a2;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Latest News from {page_title}</h1>
        <div id="news-container">
            {articles_html}
        </div>
    </div>
</body>
</html>
        """
        
        # Create the full path for the output file.
        output_path = os.path.join(OUTPUT_DIRECTORY, filename)

        # Write the final HTML to the output file.
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(final_html)
        
        #print(f"Successfully generated {output_path}")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching feed from {url}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def main():
    """
    Main function to orchestrate the HTML generation for all feeds in a continuous loop.
    """
    # Create the output directory if it doesn't exist.
    if not os.path.exists(OUTPUT_DIRECTORY):
        print(f"Creating directory: {OUTPUT_DIRECTORY}")
        os.makedirs(OUTPUT_DIRECTORY)

    while True:
        #print("Starting a new update cycle...")
        for feed in FEEDS:
            fetch_and_generate_html(feed)
        
        # Pause for 30 minutes before the next update.
        print("Update complete. Pausing for 30 minutes...")
        time.sleep(1800)

if __name__ == "__main__":
    main()
