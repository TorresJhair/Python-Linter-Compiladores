def count_records_per_category(df, col_name):
    return df.groupby(col_name).size().reset_index(name='count')

# Example usage:
import pandas as pd

df = pd.DataFrame({
    'category': ['A', 'B', 'A', 'C', 'B', 'A'],
    'value': [1, 2, 3, 4, 5, 6]
})

col_name = "category"
result = count_records_per_category(df, col_name)

print(f"Records per category (by {col_name}):")
print(result)