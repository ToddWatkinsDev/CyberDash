import pandas as pd
import requests
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import os
import time


output_dir = "DashboardServer\static\Images"
chart_files = [
    'Attack_Severity.png',
    'Attack_Types.png',
    'Most_Attacks_Incoming.png',
    'Most_Attacks_Outgoing.png'
]


def fetch_and_process_data():
    url = "https://fortiguard.fortinet.com/api/threatmap/live/outbreak?outbreak_id=0&segment_sec=300&last_sec=3600&replay=true&limit=500"


    if not os.path.exists(output_dir):
        os.makedirs(output_dir)


    try:
        response = requests.get(url, timeout=30, verify=False)
        response.raise_for_status()
        data = response.json()


        ips_data = data.get('ips', {})


        all_attacks = []
        for timestamp_key, attacks in ips_data.items():
            for attack in attacks:
                count = attack.get('count', 0)
                if count == 0:
                    continue
                for _ in range(count):
                    all_attacks.append({
                        'severity': attack.get('severity', 'Unknown'),
                        'profile_type': attack.get('profile_type', 'Unknown'),
                        'dest_country': attack.get('dest_country', 'Unknown'),
                        'src_country': attack.get('src_country', 'Unknown')
                    })


        if not all_attacks:
            return None


        df_attacks = pd.DataFrame(all_attacks)
        return df_attacks


    except Exception:
        return None


def delete_old_charts():
    for file in chart_files:
        path = os.path.join(output_dir, file)
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


def generate_charts(df_attacks):
    try:
        plt.figure(figsize=(6,6))
        df_attacks['severity'].value_counts().plot.pie(autopct='%1.1f%%', startangle=140, colors=sns.color_palette("pastel"))
        plt.title('Attack Severity Distribution')
        plt.ylabel('')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'Attack_Severity.png'))
        plt.close()


        plt.figure(figsize=(6,6))
        df_attacks['profile_type'].value_counts().plot.pie(autopct='%1.1f%%', startangle=140, colors=sns.color_palette("pastel"))
        plt.title('Attack Types Distribution')
        plt.ylabel('')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'Attack_Types.png'))
        plt.close()


        plt.figure(figsize=(10,6))
        sns.barplot(x=df_attacks['dest_country'].value_counts().head(10).values,
                    y=df_attacks['dest_country'].value_counts().head(10).index,
                    palette="viridis")
        plt.title('Most Attacks Incoming by Country (Top 10)')
        plt.xlabel('Number of Attacks')
        plt.ylabel('Destination Country')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'Most_Attacks_Incoming.png'))
        plt.close()


        plt.figure(figsize=(10,6))
        sns.barplot(x=df_attacks['src_country'].value_counts().head(10).values,
                    y=df_attacks['src_country'].value_counts().head(10).index,
                    palette="viridis")
        plt.title('Most Attacks Outgoing by Country (Top 10)')
        plt.xlabel('Number of Attacks')
        plt.ylabel('Source Country')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'Most_Attacks_Outgoing.png'))
        plt.close()


    except Exception:
        pass


if __name__ == '__main__':
    while True:
        df_attacks = fetch_and_process_data()
        if df_attacks is not None:
            delete_old_charts()
            generate_charts(df_attacks)
        print("Fortiscraper sleeping 1 minute")
        time.sleep(60)  # Wait 1 minute before next fetch

