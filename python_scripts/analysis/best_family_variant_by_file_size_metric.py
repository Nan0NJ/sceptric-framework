import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
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

# Output folder path (in project root/charts/)
output_folder = project_root / 'charts' / 'variant_overall_comparison'
output_folder.mkdir(parents=True, exist_ok=True)

# --- Load & preprocess -------------------------------------------------------

# Load data
df = pd.read_csv(csv_path)

# Extract variant, family, and file size
df['variant'] = df['algorithm'].apply(lambda x: x.split('_db/')[0])
df['family'] = df['variant'].apply(lambda x: x.split('_')[0])
df['mode'] = df['variant'].str.extract(r'^[^_]+_([^_]+)', expand=False).fillna('unknown')

# Metrics to analyze, set label and proper conversion
metrics = {
    'avg_execution_time': {'label': 'Execution Time (ms)', 'scale': 1/1_000_000},
    'avg_cpu_load': {'label': 'CPU Load (%)', 'scale': 1},
    'avg_memory_used': {'label': 'Memory Used (MB)', 'scale': 1/1024},
    'avg_cpu_power': {'label': 'CPU Power (W)', 'scale': 1},
    'avg_energy_consumption': {'label': 'Energy Consumption (mJ)', 'scale': 1_000}
}

# Set theme
sns.set_theme(context='talk', style='whitegrid', font='Arial', font_scale=1.1)

# Compute composite point scores per family
for family in sorted(df['family'].unique()):
    sub = df[df['family'] == family].copy()
    if sub.empty:
        continue

    # Collect per-mode aggregated metric
    agg_list = []
    for col, props in metrics.items():
        scale = props['scale']
        sub[f'value_{col}'] = sub[col] * scale
        grp = sub.groupby('mode')[f'value_{col}'].mean().rename(props['label'])
        agg_list.append(grp)
    means = pd.concat(agg_list, axis=1)

    # Rank modes per metric (1 = BEST)
    ranks = means.rank(method='min', ascending=True)
    M = len(means)

    # Convert ranks to points and sum
    points = (M - ranks + 1)
    points['Total Points'] = points.sum(axis=1)
    composite = points.sort_values('Total Points', ascending=False)

    # Save composite CSV
    out_csv = output_folder / f'{family}_mode_composite_scores.csv'
    composite.to_csv(out_csv, index_label='mode')

    # Prepare data for plotting
    plot_df = composite.reset_index()
    palette_dict = dict(zip(plot_df['mode'], ['#2E7D32' if i == 0 else '#4682B4' for i in range(len(plot_df))]))  # More refined colors

    # Plot composite bar chart
    plt.figure(figsize=(8, max(4, M * 0.8)), facecolor='white')
    ax = sns.barplot(
        x='Total Points',
        y='mode',
        hue='mode',
        data=plot_df,
        palette=palette_dict,
        dodge=False,
        legend=False,
        edgecolor='black',
        linewidth=1.2
    )

    # Title and labels
    ax.set_title(f'{family} Modes Composite Score (Borda Count Points)', pad=15, fontsize=14, fontweight='bold')
    ax.set_xlabel('Total Points', fontsize=12)
    ax.set_ylabel('Variant', fontsize=12)

    # Ticks and grid
    ax.tick_params(axis='both', labelsize=10)
    ax.grid(True, axis='x', linestyle='--', alpha=0.7)

    # Identify the maximum points and style all tied modes
    max_points = composite['Total Points'].max()
    for i, row in plot_df.iterrows():
        ax.text(
            row['Total Points'] - 0.5,
            i,
            f"{int(row['Total Points'])}",
            va='center',
            ha='right',
            color='white',
            fontsize=10,
            fontweight='bold'
        )
        # Update palette dynamically for ties
        if row['Total Points'] == max_points:
            ax.patches[i].set_color('#2E7D32')  # Apply top color to all tied modes
            ax.patches[i].set_edgecolor('black')
            ax.patches[i].set_linewidth(1.2)

    # X-axis limit to avoid crowding
    ax.set_xlim(0, composite['Total Points'].max() * 1.1)

    # Spines removed for a cleaner look
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_linewidth(1.2)
    ax.spines['bottom'].set_linewidth(1.2)

    plt.tight_layout()
    out_png = output_folder / f'{family}_composite_score.png'
    plt.savefig(out_png, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()

print(f'Composite scores and charts saved under: {output_folder}')