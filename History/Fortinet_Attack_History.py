import pandas as pd
import requests
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
import os
import schedule
import time
import threading
import keyboard  # pip install keyboard

output_dir = "History/"
run_job_now = False  # Flag for immediate job trigger

def manage_data():
    data_file_path = os.path.join(output_dir, 'cyberattack_data.csv')

    if os.path.exists(data_file_path) and os.path.getsize(data_file_path) == 0:
        print("CSV file empty, writing header row.")
        pd.DataFrame(columns=['timestamp', 'attacks']).to_csv(data_file_path, index=False)

    existing_df = pd.DataFrame(columns=['timestamp', 'attacks'])
    if os.path.exists(data_file_path):
        try:
            print(f"Loaded {len(existing_df)} records from existing CSV.")
        except pd.errors.EmptyDataError:
            print("CSV file empty after header write, starting fresh.")
        except Exception as e:
            print(f"Error reading CSV: {e}")

    url = "https://fortiguard.fortinet.com/api/threatmap/live/outbreak?outbreak_id=0&segment_sec=300&last_sec=3600&replay=true&limit=500"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    print("Fetching new data from API...")

    try:
        response = requests.get(url, timeout=30, verify=False)
        response.raise_for_status()

        data = response.json()
        threat_data = data.get('ips', {})
        new_data = []

        for timestamp, attacks_list in threat_data.items():
            for item in attacks_list:
                timestamp_ms = int(item.get('redis_ms', '0-0').split('-')[0])
                ts = datetime.fromtimestamp(timestamp_ms / 1000)
                count = item.get('count', 0)
                new_data.append({'timestamp': ts, 'attacks': count})

        new_df = pd.DataFrame(new_data)
        new_df['timestamp'] = pd.to_datetime(new_df['timestamp'])

        combined_df = pd.concat([existing_df, new_df]).drop_duplicates(subset=['timestamp']).sort_values(by='timestamp')

        twelve_hours_ago = datetime.now() - timedelta(hours=12)
        filtered_df = combined_df[combined_df['timestamp'] > twelve_hours_ago]

        print(f"Filtered to {len(filtered_df)} records from last 12 hours.")

        if filtered_df.empty:
            print("No data after filtering; CSV not updated.")
        else:
            filtered_df.to_csv(data_file_path, index=False)
            print("Updated CSV saved successfully.")

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}")
    except (KeyError, ValueError) as e:
        print(f"Data format issue: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

def create_and_save_plot():
    data_file_path = os.path.join(output_dir, 'cyberattack_data.csv')

    if not os.path.exists(data_file_path):
        print("CSV not found. Skipping plot creation.")
        return

    df = pd.read_csv(data_file_path, parse_dates=['timestamp'])
    if df.empty:
        print("CSV empty. Skipping plot creation.")
        return

    now = datetime.now()
    df['relative_hour'] = (df['timestamp'] - now).dt.total_seconds() / 3600

    df = df.sort_values('timestamp')

    df['attacks_rolling_avg'] = df.set_index('timestamp')['attacks'] \
        .rolling('1h', closed='right') \
        .mean() \
        .reset_index(drop=True)

    plt.clf()
    fig, ax = plt.subplots(figsize=(12, 7))
    sns.set_style("darkgrid")

    sns.lineplot(data=df, x='relative_hour', y='attacks', ax=ax, label='Attacks')
    sns.lineplot(data=df, x='relative_hour', y='attacks_rolling_avg', ax=ax, label='Rolling Average (1h)', color='orange')

    ax.grid(True, which='both', axis='both', linestyle='--', linewidth=0.7, alpha=0.7)  # Explicit grid

    ax.set_xlim(-12, 0)
    ax.set_xticks([-12, -9, -6, -3, 0])
    ax.set_xticklabels(['-12 Hours', '-9', '-6', '-3', '0 Hours'])
    ax.set_title('Real-time Cyberattack Trends')
    ax.set_xlabel('Hours Ago')
    ax.set_ylabel('Number of Attacks')
    ax.legend(title='Legend', loc='upper left', fontsize='medium')

    plt.tight_layout()

    filename = "attack_trends.png"
    file_path = os.path.join(output_dir, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Deleted old plot file: {filename}")

    plt.savefig(file_path)
    print(f"Plot saved as {filename}")

def job():
    print(f"Scheduled job started at {datetime.now()}.")
    manage_data()
    create_and_save_plot()
    print(f"Scheduled job completed at {datetime.now()}.")

def hotkey_listener():
    global run_job_now
    # Hotkey Ctrl+Shift+S+K to trigger immediate job
    keyboard.add_hotkey('ctrl+shift+s+k', lambda: trigger_job())

def trigger_job():
    global run_job_now
    print(f"Backdoor hotkey Ctrl+Shift+S+K pressed at {datetime.now()}. Running job now.")
    run_job_now = True

if __name__ == "__main__":
    schedule.every(30).minutes.do(job)
    print("Scheduler started, job will run every 30 minutes.")
    job()

    listener_thread = threading.Thread(target=hotkey_listener, daemon=True)
    listener_thread.start()

    while True:
        schedule.run_pending()
        if run_job_now:
            job()
            run_job_now = False
        time.sleep(1)
