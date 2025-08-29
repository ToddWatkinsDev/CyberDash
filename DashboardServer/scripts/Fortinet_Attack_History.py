import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
import pytz  # pip install pytz

output_dir = "DashboardServer/static/Images"
run_job_now = False  # Flag for immediate job trigger

def manage_data():
    data_file_path = os.path.join(output_dir, 'cyberattack_data.csv')

    if os.path.exists(data_file_path) and os.path.getsize(data_file_path) == 0:
        pd.DataFrame(columns=['timestamp', 'attacks']).to_csv(data_file_path, index=False)

    existing_df = pd.DataFrame(columns=['timestamp', 'attacks'])
    if os.path.exists(data_file_path):
        try:
            existing_df = pd.read_csv(data_file_path)
            existing_df['timestamp'] = pd.to_datetime(existing_df['timestamp'], errors='coerce')
            existing_df = existing_df.dropna(subset=['timestamp'])
            if existing_df['timestamp'].dt.tz is None:
                existing_df['timestamp'] = existing_df['timestamp'].dt.tz_localize('Europe/Jersey')
            else:
                existing_df['timestamp'] = existing_df['timestamp'].dt.tz_convert('Europe/Jersey')
        except pd.errors.EmptyDataError:
            pass
        except Exception as e:
            print(f"[ERROR] Exception reading CSV: {e}")

    url = "https://fortiguard.fortinet.com/api/threatmap/live/outbreak?outbreak_id=0&segment_sec=300&last_sec=3600&replay=true&limit=500"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        response = requests.get(url, timeout=30, verify=False)
        response.raise_for_status()

        data = response.json()
        threat_data = data.get('ips', {})
        new_data = []
        jersey_tz = pytz.timezone('Europe/Jersey')

        for timestamp, attacks_list in threat_data.items():
            for item in attacks_list:
                timestamp_ms = int(item.get('redis_ms', '0-0').split('-')[0])
                utc_time = datetime.utcfromtimestamp(timestamp_ms / 1000).replace(tzinfo=pytz.UTC)
                jersey_time = utc_time.astimezone(jersey_tz)
                count = item.get('count', 0)
                new_data.append({'timestamp': jersey_time, 'attacks': count})

        new_df = pd.DataFrame(new_data)

        if not new_df.empty:
            new_df['timestamp'] = pd.to_datetime(new_df['timestamp']).dt.tz_convert('Europe/Jersey')

        existing_df_clean = existing_df.dropna(axis=1, how='all') if not existing_df.empty else existing_df
        new_df_clean = new_df.dropna(axis=1, how='all') if not new_df.empty else new_df

        if not existing_df_clean.empty and not new_df_clean.empty:
            combined_df = pd.concat([existing_df_clean, new_df_clean]).drop_duplicates(subset=['timestamp']).sort_values(by='timestamp')
        elif not existing_df_clean.empty:
            combined_df = existing_df_clean.copy()
        elif not new_df_clean.empty:
            combined_df = new_df_clean.copy()
        else:
            combined_df = pd.DataFrame(columns=['timestamp', 'attacks'])

        combined_df['timestamp'] = pd.to_datetime(combined_df['timestamp'], errors='coerce')
        combined_df = combined_df.dropna(subset=['timestamp'])
        if combined_df['timestamp'].dt.tz is None:
            combined_df['timestamp'] = combined_df['timestamp'].dt.tz_localize('Europe/Jersey')
        else:
            combined_df['timestamp'] = combined_df['timestamp'].dt.tz_convert('Europe/Jersey')

        twelve_hours_ago = datetime.now(jersey_tz) - timedelta(hours=12)
        filtered_df = combined_df[combined_df['timestamp'] > twelve_hours_ago]

        if not filtered_df.empty:
            filtered_df.to_csv(data_file_path, index=False)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request error: {e}")
    except (KeyError, ValueError) as e:
        print(f"[ERROR] Data format issue: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")

def create_and_save_plot():
    data_file_path = os.path.join(output_dir, 'cyberattack_data.csv')

    if not os.path.exists(data_file_path):
        return

    df = pd.read_csv(data_file_path, parse_dates=['timestamp'])
    jersey_tz = pytz.timezone('Europe/Jersey')
    if df.empty:
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.dropna(subset=['timestamp'])

    if df['timestamp'].dt.tz is None:
        df['timestamp'] = df['timestamp'].dt.tz_localize('Europe/Jersey')
    else:
        df['timestamp'] = df['timestamp'].dt.tz_convert('Europe/Jersey')

    now = datetime.now(jersey_tz)
    df['relative_hour'] = (df['timestamp'] - now).dt.total_seconds() / 3600
    df = df.sort_values('timestamp')

    df['attacks_rolling_avg'] = (
        df.set_index('timestamp')['attacks']
        .rolling('1h', closed='right')
        .mean()
        .reset_index(drop=True)
    )

    plt.clf()
    fig, ax = plt.subplots(figsize=(12, 7))
    sns.set_style("darkgrid")
    sns.lineplot(data=df, x='relative_hour', y='attacks', ax=ax, label='Attacks')
    sns.lineplot(data=df, x='relative_hour', y='attacks_rolling_avg', ax=ax, label='Rolling Average (1h)', color='orange')

    ax.grid(True, which='both', axis='both', linestyle='--', linewidth=0.7, alpha=0.7)
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

    plt.savefig(file_path)

def job():
    manage_data()
    create_and_save_plot()

def hotkey_listener():
    global run_job_now
    keyboard.add_hotkey('ctrl+shift+s+k', lambda: trigger_job())

def trigger_job():
    global run_job_now
    run_job_now = True

if __name__ == "__main__":
    schedule.every(30).minutes.do(job)
    job()
    print("History next 30 Mins")

    listener_thread = threading.Thread(target=hotkey_listener, daemon=True)
    listener_thread.start()

    while True:
        schedule.run_pending()
        if run_job_now:
            job()
            run_job_now = False
        time.sleep(1)

