import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from math import pi
from pathlib import Path

# --- Paths setup --------------------------------------------------------------

# Get the script's absolute path and directory
script_path = Path(__file__).resolve()
script_dir = script_path.parent

# Navigate to project root (adjust based on your structure)
project_root = script_dir.parent.parent

# Path to CSV
csv_path = project_root / 'python_scripts' / 'main_algorithm_performance_summary.csv'
if not csv_path.exists():
    raise FileNotFoundError(f"CSV file not found at: {csv_path}")

# Output folder
output_dir = project_root / 'charts' / 'radar_fingerprint_per_family'
output_dir.mkdir(parents=True, exist_ok=True)

# --- Load & preprocess -------------------------------------------------------

# Load and preprocess data
df = pd.read_csv(csv_path)

# Extract variant and family
df['variant'] = df['algorithm'].apply(lambda x: x.split('_db/')[0] if '_db/' in x else x.split('_plaintext')[0])
df['family'] = df['variant'].apply(lambda x: x.split('_')[0])

# Metrics analysis (Categories)
metrics = ['avg_execution_time', 'avg_cpu_load', 'avg_memory_used', 'avg_cpu_power', 'avg_energy_consumption']
categories = [m.replace('avg_', '').replace('_', ' ').title() for m in metrics]
N = len(metrics)
angles = [n / float(N) * 2 * pi for n in range(N)]
offset = pi / 4  # Start at 45 degrees (pi/4 radians)
angles = [(angle + offset) % (2 * pi) for angle in angles]
angles += angles[:1]  # Close the loop

# Find best-performing variant per family by avg_execution_time
df_best = df.loc[df.groupby('family')['avg_execution_time'].idxmin()].copy()
df_best.set_index('family', inplace=True)

# Normalize metrics (lower is better, so invert by subtracting from 1)
scaler = MinMaxScaler()
normalized = scaler.fit_transform(df_best[metrics])
normalized = 1 - normalized  # Invert since lower values are better
norm_df = pd.DataFrame(normalized, index=df_best.index, columns=metrics)

# --- Plot individual radar charts for each family ---
for i, (family, row) in enumerate(norm_df.iterrows()):
    fig, ax = plt.subplots(figsize=(8, 8), subplot_kw=dict(polar=True))
    values = row.tolist() + [row.tolist()[0]]  # Close the loop
    color = '#1E90FF'
    ax.plot(angles, values, color=color, linewidth=2, label=family)
    ax.fill(angles, values, color=color, alpha=0.25)

    # Axis formatting
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories, fontsize=12)
    ax.set_rlabel_position(0)
    plt.yticks([0.2, 0.4, 0.6, 0.8, 1.0], ["0.2", "0.4", "0.6", "0.8", "1.0"], color="grey", size=10)
    plt.ylim(0, 1)
    plt.title(f"Radar Fingerprint – {family} (Best Variant: {df_best.loc[family, 'variant']})", size=14, pad=20)
    plt.legend(loc='upper right', fontsize=10)

    # Save individual chart
    plt.savefig(output_dir / f"radar_fingerprint_{family}.png", dpi=300, bbox_inches='tight')
    plt.close()

# --- Select top-performing families for combined chart ---
# Compute an overall score for each family by averaging normalized metrics
norm_df['overall_score'] = norm_df[metrics].mean(axis=1)
# Sort by overall score and select top 4 families for better visualization
top_families = norm_df.sort_values(by='overall_score', ascending=False).head(4).index
norm_df_top = norm_df.loc[top_families]

# --- Plot combined radar chart for top families ---
fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))

# Use a smaller set of distinct colors for better differentiation
colors = ['#FF6347', '#32CD32', '#1E90FF', '#DAA520']

for i, (family, row) in enumerate(norm_df_top.iterrows()):
    values = row[metrics].tolist() + [row[metrics].tolist()[0]]  # Close the loop
    ax.plot(angles, values, color=colors[i], linewidth=2.5, label=family)
    ax.fill(angles, values, color=colors[i], alpha=0.2)

# Axis formatting
ax.set_xticks(angles[:-1])
ax.set_xticklabels(categories, fontsize=12)
ax.set_rlabel_position(0)
plt.yticks([0.2, 0.4, 0.6, 0.8, 1.0], ["0.2", "0.4", "0.6", "0.8", "1.0"], color="grey", size=10)
plt.ylim(0, 1)
plt.title("Radar Fingerprint – Top 4 Best Variants by Overall Performance", size=16, pad=20)
plt.legend(bbox_to_anchor=(1.1, 1.1), loc='upper left', fontsize=12, title="Top Families")

# Save combined chart
plt.savefig(output_dir / "radar_fingerprint_top_families.png", dpi=300, bbox_inches='tight')
plt.close()