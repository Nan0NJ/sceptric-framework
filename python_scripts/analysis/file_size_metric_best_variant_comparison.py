import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from matplotlib import colormaps
from matplotlib.colors import Normalize

# --- Paths setup --------------------------------------------------------------

# Get the script's absolute path and directory
script_path = Path(__file__).resolve()
script_dir  = script_path.parent

# Navigate to project root (adjust based on your structure)
project_root = script_dir.parent.parent

# Path to CSV
csv_path = project_root / 'python_scripts' / 'main_algorithm_performance_summary.csv'
if not csv_path.exists():
    raise FileNotFoundError(f"CSV file not found at: {csv_path}")

# Output folder path (in project root/charts/)
output_folder = project_root / 'charts' / 'histogram_best_variant_comparison_file_size_and_metric'
output_folder.mkdir(parents=True, exist_ok=True)

# --- Load & preprocess -------------------------------------------------------

# Load data
df = pd.read_csv(csv_path)

# Extract variant, family, and file size
df['variant']   = df['algorithm'].apply(lambda x: x.split('_db/')[0])
df['family']    = df['variant'].apply(lambda x: x.split('_')[0])
df['file_size'] = df['algorithm'].apply(
    lambda x: re.search(r'plaintext_([^/]+)\.txt', x).group(1)
)

# Metrics to analyze
metrics = [
    'execution_time',
    'cpu_load',
    'memory_used',
    'cpu_power',
    'energy_consumption'
]
# Metric Labels
metric_labels = {
    'execution_time':     'Execution Time (ms)',
    'cpu_load':           'CPU Load (%)',
    'memory_used':        'Memory Used (MB)',
    'cpu_power':          'CPU Power (W)',
    'energy_consumption': 'Energy Consumption (mJ)'
}

# --- Phase 1: find the best variant per family on size/metric -----------------------

best_results = []
for family in df['family'].unique():
    for size in sorted(
            df['file_size'].unique(),
            key=lambda x: int(re.findall(r'\d+', x)[0])
    ):
        for metric in metrics:
            col = f'avg_{metric}'
            subset = df[(df['family']==family) & (df['file_size']==size)]
            if subset.empty:
                continue
            idx  = subset[col].idxmin()
            best = subset.loc[idx]
            best_results.append({
                'family':      family,
                'file_size':   size,
                'metric':      metric,
                'best_variant': best['variant'],
                'value':       best[col]
            })

best_df = pd.DataFrame(best_results)

# --- Phase 2: plot with seaborn + gradient colors ----------------------------

# Presentation-ready style
sns.set_theme(context='talk', style='whitegrid')

for metric in metrics:
    pretty = metric_labels[metric]
    for size in sorted(
            best_df['file_size'].unique(),
            key=lambda x: int(re.findall(r'\d+', x)[0])):
        sub = best_df[(best_df['metric']==metric) & (best_df['file_size']==size)]
        if sub.empty:
            continue

        # Prepare DataFrame for seaborn
        plot_df = sub[['family','value']].copy()
        plot_df['is_best'] = plot_df['value'] == plot_df['value'].min()

        # Convert units
        if metric == 'execution_time':
            plot_df['value'] = plot_df['value'] / 1_000_000  # ns → ms
        elif metric == 'memory_used':
            plot_df['value'] = plot_df['value'] / 1024  # KB → MB
        elif metric == 'energy_consumption':
            plot_df['value'] = plot_df['value'] * 1_000  # J → mJ

        # Detect extremes (using IQR rule)
        q1 = plot_df['value'].quantile(0.25)
        q3 = plot_df['value'].quantile(0.75)
        iqr = q3 - q1
        threshold = q3 + 1.5 * iqr
        extremes = plot_df[plot_df['value'] > threshold]


        # Define a plotting function
        def make_plot(df_to_plot, suffix, title_suffix):
            norm = Normalize(vmin=df_to_plot['value'].min(), vmax=df_to_plot['value'].max())
            cmap = colormaps['RdYlGn_r']
            colors = [cmap(norm(v)) for v in df_to_plot['value']]
            palette = dict(zip(df_to_plot['family'], colors))

            # Ensure unique labels
            decimals = 2
            labels = [f"{v:.{decimals}f}" for v in df_to_plot['value']]
            while len(set(labels)) < len(labels) and decimals < 8:
                decimals += 1
                labels = [f"{v:.{decimals}f}" for v in df_to_plot['value']]

            plt.figure(figsize=(12, 8))
            ax = sns.barplot(
                data=df_to_plot,
                x='family', y='value',
                hue='family',
                palette=palette,
                dodge=False,
                legend=False
            )

            ax.set_title(f'Algorithm Comparison – File Size {size} – {pretty}{title_suffix}', pad=16)
            ax.set_xlabel('Algorithm Family', labelpad=12)
            ax.set_ylabel(f'Average {pretty}', labelpad=12)
            ax.tick_params(axis='x', rotation=45)

            for bar, txt, (_, row) in zip(ax.patches, labels, df_to_plot.iterrows()):
                color = 'darkgreen' if row['is_best'] else 'black'
                weight = 'bold' if row['is_best'] else 'normal'
                h = row['value']
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    h + (h * 0.01),
                    txt,
                    ha='center', va='bottom',
                    color=color, fontweight=weight, fontsize=12
                )

            sns.despine(left=True, bottom=True)
            plt.tight_layout()
            fname = f'{metric}_{size}{suffix}.png'
            plt.savefig(output_folder / fname, dpi=300)
            plt.close()


        # Plot full data
        make_plot(plot_df, suffix='', title_suffix='')

        # Plot without extremes if any detected
        if not extremes.empty:
            filtered = plot_df[plot_df['value'] <= threshold]
            make_plot(filtered, suffix='_no_extreme', title_suffix=' (Outliers Removed)')

    print('Histograms saved in:', output_folder)