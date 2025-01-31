# mscp/generate/local_report.py

# Standard python modules
import logging
import argparse
import sys
import base64
import tempfile

from io import BytesIO
from pathlib import Path
from icecream import ic

# Additional python modules
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from openpyxl import Workbook
from openpyxl.drawing.text import Paragraph, ParagraphProperties, CharacterProperties
from openpyxl.styles import Alignment
from openpyxl.chart import PieChart, Reference
from openpyxl.chart.label import DataLabelList
from openpyxl.chart.legend import Legend
from openpyxl.chart.title import Title
from openpyxl.chart.text import RichText, Text
from openpyxl.chart.data_source import StrRef
from openpyxl.styles import Alignment
from jinja2 import Environment, FileSystemLoader

# Local python modules
from src.mscp.common_utils.config import config
from src.mscp.common_utils.file_handling import open_plist
from src.mscp.common_utils.sanatize_input import sanitized_input


# Initialize local logger
logger = logging.getLogger(__name__)


def generate_local_report(args: argparse.Namespace) -> None:
    """
    Generates a local compliance report based on the provided arguments.

    Args:
        args (argparse.Namespace): Command-line arguments containing options for generating the report.

    The function performs the following steps:
    1. Determines the output paths for the Excel and HTML reports.
    2. Loads the plist data either from a specified file or by prompting the user to select one from a directory.
    3. Extracts relevant data from the plist file and creates a pandas DataFrame.
    4. Converts the DataFrame's 'Result' column from boolean to 'Passed' or 'Failed'.
    5. Generates an Excel report with the compliance data, adjusts column widths, and centers the 'Result' column.
    6. Creates a pie chart of the compliance results and inserts it into the Excel report.
    7. Renders an HTML report using a Jinja2 template, embedding the pie chart as a base64-encoded image and including the DataFrame as an HTML table.
    8. Writes the rendered HTML report to the specified output path.

    Raises:
        SystemExit: If no plist files are found or if an invalid plist file selection is made.
    """
    plist_data: dict = {}
    excel_output_path: Path = Path(config["output_dir"], "compliance_report.xlsx")
    html_output_path: Path = Path(config["output_dir"], "compliance_report.html")

    if args.output:
        excel_output_path = args.output
        html_output_path = Path(args.output.parent, f"{args.output.stem}.html")

    logger.debug(f"Excel output path: {excel_output_path}")
    logger.debug(f"HTML output path: {html_output_path}")

    if args.plist:
        plist_data = open_plist(args.plist)
    else:
        plist_dir = Path("/Library/Preferences")
        plist_files = list(plist_dir.glob("org.*.audit.plist"))

        if not plist_files:
            logger.error("No plist files found in /Library/Preferences")
            sys.exit(1)

        print("Available plist files:")
        for idx, plist in enumerate(plist_files, start=1):
            print(f"{idx}: {plist.name}")

        choice = sanitized_input("Select the number of the plist file you want to use: ", type_=int)

        try:
            choice_idx = int(choice) - 1
            if choice_idx < 0 or choice_idx >= len(plist_files):
                raise ValueError
            plist_data = open_plist(plist_files[choice_idx])
        except ValueError:
            logger.error("Invalid selection")
            sys.exit(1)

    env: Environment = Environment(loader=FileSystemLoader(f"{config['defaults']['templates_dir']}/local_report"), trim_blocks=True, lstrip_blocks=True)
    html_template_file = env.get_template('local_report.html.jinja')

    # Extract data from plist file
    data: list[dict[str,bool]] = [{"Rule ID": rule_id, "Result": details.get("finding", False)} for rule_id, details in plist_data.items() if isinstance(details, dict)]

    # Create DataFrame
    df = pd.DataFrame(data)
    df.sort_values(by=['Rule ID'], inplace=True)

    # Convert Result from bool to 'Passed' or 'Finding'
    df['Result'] = df['Result'].apply(lambda x: 'Finding' if x else 'Passed')

    # Create Excel file
    with pd.ExcelWriter(excel_output_path, engine='openpyxl', mode='w') as writer:
        df.to_excel(writer, index=False, sheet_name='Local Report')

        # Adjust column width
        workbook = writer.book
        worksheet = writer.sheets['Local Report']
        for column in worksheet.columns:
            max_length = 0
            column_letter = column[0].column_letter
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(cell.value)
                except:
                    pass
            adjusted_width = (max_length + 2)
            worksheet.column_dimensions[column_letter].width = adjusted_width

        # Center align the Result column
        for cell in worksheet['B']:
            cell.alignment = Alignment(horizontal='center', vertical='center')

        # Create Pie chart
        result_counts: pd.Series[int] = df['Result'].value_counts()
        fig, ax = plt.subplots()
        result_counts.plot.pie(ax=ax, autopct='%1.1f%%', startangle=90, labels=result_counts.index)
        ax.set_ylabel('')
        ax.set_title('Compliance Scan Results')
        ax.legend()

        # Save pie chart as image
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            img_path = Path(tmpfile.name)
        plt.savefig(img_path)
        plt.close(fig)

        # Insert pie chart into Excel
        minrow: int = df['Result'].count() + 2
        maxrow: int = df['Result'].count() + 3

        # Create a PieChart
        pie = PieChart()
        labels = Reference(worksheet, min_col=1, min_row=minrow, max_row=maxrow)
        sheet_data = Reference(worksheet, min_col=2, min_row=minrow, max_row=maxrow)

        for result, count in result_counts.items():
            worksheet.append([result, count])

        pie.add_data(sheet_data)
        pie.set_categories(labels)
        pie.title = "Compliance Scan Results"
        pie.legend = Legend()

        # Add the chart to the worksheet
        worksheet.add_chart(pie, "D1")

    encoded_string = base64.b64encode(img_path.read_bytes()).decode()

    rendered_output = html_template_file.render(
        encoded_image=encoded_string,
        dataframe=df.to_html(index=False, border=0),
        passed_value=result_counts.get('Passed', 0),
        failed_value=result_counts.get('Finding', 0)
    )

    html_output_path.write_text(rendered_output)
