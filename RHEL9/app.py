import dash
from dash import dcc, html, Input, Output, State
import pandas as pd
import plotly.graph_objects as go
from flask import Flask, send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from io import BytesIO

server = Flask(__name__)
app = dash.Dash(__name__, server=server)
app.config.suppress_callback_exceptions = True

excel_file = 'CIS_RHEL9_Hardening_Report.xlsx'
sheets = pd.ExcelFile(excel_file).sheet_names

module_data = {}
total_success = 0
total_failure = 0

for sheet_name in sheets:
    df = pd.read_excel(excel_file, sheet_name=sheet_name)
    if 'Value' in df.columns:
        failures = df[df['Value'] == False]
        failure_count = len(failures)
        module_data[sheet_name] = {
            'failures': failure_count,
            'details': failures[['Expected Output', 'Actual Output']] if {'Expected Output', 'Actual Output'}.issubset(df.columns) else pd.DataFrame()
        }
        total_failure += failure_count
        total_success += (len(df) - failure_count)
    else:
        print(f"Sheet '{sheet_name}' does not contain a 'Value' column.")

def generate_pie_chart_image():
    fig = go.Figure(data=[go.Pie(
        labels=['Success', 'Failure'],
        values=[total_success, total_failure],
        marker=dict(colors=['#2ECC71', '#ff5733']),
        textinfo='label+percent'
    )])
    fig.update_layout(width=600, height=600)
    img_bytes = fig.to_image(format="png")
    return ImageReader(BytesIO(img_bytes))

app.layout = html.Div([
    dcc.Loading(id="loading-spinner", type="circle", children=[
        html.Div(
            className="sidebar",
            children=[
                html.H2(html.Img(src="assets/logo.png", className="sidebar-logo"), className="sidebar-title"),
                html.Ul([
                    html.Li(html.A("Dashboard", href="#", id="dashboard-link")),
                    html.Li(html.A("Resource Links", href="#", id="resource-link")),
                    html.Li(html.A("About Us", href="#", id="about-link")),
                ], className="sidebar-menu"),
            ],
        ),
        html.Div(id="content", className="content")
    ])
])

dashboard_content = html.Div([
    html.H1(html.Img(src="assets/logo.png", className="secure-sys-logo"), className="secure-sys-title"),
    html.Div(
        id='module-container',
        children=[
            html.Div(
                [
                    html.H3(f"{module}", className="module-title"),
                    html.P(module_data[module]['failures'], className="module-count")
                ],
                className='module-tile',
                id=f"tile-{module}",
                n_clicks=0,
                **{"data-failure": str(module_data[module]['failures'] > 0).lower()}
            ) for module in module_data
        ]
    ),
    dcc.Graph(id='pie-chart', figure=go.Figure(data=[go.Pie(
        labels=['Success', 'Failure'],
        values=[total_success, total_failure],
        marker=dict(colors=['#2ECC71', '#ff5733']),
        textinfo='label+percent'
    )]), style={'margin-top': '20px'}),
    html.A("Download as PDF", href="/download_pdf", target="_blank", className="download-button"),
    html.Div(id='details-container', style={'margin-top': '20px'})
])

resource_links_content = html.Div([
    html.H1("Resource Links", className="title"),
    html.Div([
        dcc.Input(id="search-bar", type="text", placeholder="Search articles or videos..."),
        html.Button("Search", id="search-button", n_clicks=0)
    ], className="search-container"),
    html.Div(id="search-results", className="video-container", children=[
        html.Div(className="video-item", children=[
            html.Img(src="https://img.youtube.com/vi/Jnxx_IAC0G4/0.jpg", className="video-thumbnail"),
            html.A("10 Tips for Hardening your Linux Servers", href="https://youtu.be/Jnxx_IAC0G4?si=Wfw5DA7PlbakjDmy", target="_blank", className="video-title")
        ]),
        html.Div(className="video-item", children=[
            html.Img(src="https://img.youtube.com/vi/Sa0KqbpLye4/0.jpg", className="video-thumbnail"),
            html.A("The COMPLETE Linux Hardening, Privacy & Security Guide!", href="https://youtu.be/Sa0KqbpLye4?si=JPzydKdz5zkFtBnm", target="_blank", className="video-title")
        ]),
        html.Div(className="video-item", children=[
            html.Img(src="https://img.youtube.com/vi/d2hCS6T1z3k/0.jpg", className="video-thumbnail"),
            html.A("The Ultimate Guide to Linux Hardening: Boost Your System Security [HINDI]", href="https://youtu.be/d2hCS6T1z3k?si=GP7aQcfwolroV72L", target="_blank", className="video-title")
        ]),
        html.Div(className="video-item", children=[
            html.Img(src="https://img.youtube.com/vi/AwrKXtI_tJA/0.jpg", className="video-thumbnail"),
            html.A("Linux Security Hardening - CIS Level1 on RHEL8.7", href="https://youtu.be/AwrKXtI_tJA?si=bc8j6dcEqNXSYvrt", target="_blank", className="video-title")
        ]),
        html.Div(className="video-item", children=[
            html.Img(src="https://img.youtube.com/vi/TVTQcEWMQa0/0.jpg", className="video-thumbnail"),
            html.A("How to Achieve CIS Benchmark Compliance to Harden Linux Systems | Into the Terminal 120", href="https://www.youtube.com/live/TVTQcEWMQa0?si=nyjwmQQfr3TmPEz5", target="_blank", className="video-title")
        ]),
        html.Div(className="video-item", children=[
            html.Img(src="https://img.youtube.com/vi/2orzA98Ih0k/0.jpg", className="video-thumbnail"),
            html.A("What are CIS Benchmarks? and Why are CIS Benchmarks important?", href="https://www.youtube.com/live/2orzA98Ih0k?si=iz6As3tg6dvF4pZV", target="_blank", className="video-title")
        ]),
        html.Div(className="article-item", children=[
            html.H3("SecureSys", className="article-title"),
            html.P("SecureSys and how it works."),
            html.A("Learn more", href="https://github.com/ChirayuRathi03/SecureSys/blob/5fd74dc114a7a8383bd383be4b1ab67477799786/SecureSys_Universal%20Hardening%20and%20Compliance%20Toolkit.pdf", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Linux System Hardening Checklist", className="article-title"),
            html.P("This article provides an extensive checklist for hardening Linux systems..."),
            html.A("Read more", href="https://www.cyberciti.biz/tips/linux-security.html", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Server Hardening: Best Practices", className="article-title"),
            html.P("A guide on server hardening with methods to protect against threats."),
            html.A("Learn more", href="https://www.acunetix.com/blog/articles/server-hardening-best-practices/", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Linux OS Hardening: CIS Benchmarks", className="article-title"),
            html.P("Hardening is a process in which one reduces the vulnerability of resources to prevent it from cyber attacks like Denial of service, unauthorized data access, etc."),
            html.A("Learn more", href="https://opstree.com/blog/2020/04/29/linux-os-hardening-cis-benchmarks/", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Red Hat Enterprise Linux 8 Security hardening", className="article-title"),
            html.P("Learn the processes and practices for securing Red Hat Enterprise Linux servers and workstations against local and remote intrusion, exploitation, and malicious activity. By using these approaches and tools, you can create a more secure computing environment for the data center, workplace, and home."),
            html.A("Learn more", href="https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/pdf/security_hardening/Red_Hat_Enterprise_Linux-8-Security_hardening-en-US.pdf", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Red Hat Enterprise Linux 9 Security hardening", className="article-title"),
            html.P("Security begins even before you start the installation of Red Hat Enterprise Linux. Configuring your system securely from the beginning makes it easier to implement additional security settings later."),
            html.A("Learn more", href="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/pdf/security_hardening/red_hat_enterprise_linux-9-security_hardening-en-us.pdf", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Linux Server Hardening and Security Best Practices", className="article-title"),
            html.P("This guide explains how what configuration hardening is and how to establish hardened build standards for your Linux and Unix systems."),
            html.A("Learn more", href="https://www.netwrix.com/linux_hardening_security_best_practices.html#:~:text=Hardening%20a%20system%20means%20optimizing,the%20role%20of%20the%20computer", target="_blank", className="read-more-link")
        ]),
        html.Div(className="article-item", children=[
            html.H3("Windows and Linux Server Hardening: Comprehensive Checklist:", className="article-title"),
            html.P("The Liquid Web blog provides a comprehensive checklist for server hardening, covering key security measures to protect servers from vulnerabilities and cyber threats."),
            html.A("Learn more", href="https://www.liquidweb.com/blog/server-hardening-checklist/", target="_blank", className="read-more-link")
        ]),
    ])
])


about_us_content = html.Div([
    html.H1("About Us", className="title"),
    html.P([
        "SecureSys is a comprehensive automation toolkit designed to enhance cybersecurity and compliance across Linux systems. Created by ",
        html.A("Chirayu Rathi", href="https://www.linkedin.com/in/chirayu-rathi-002184230", target="_blank"),
        ", ",
        html.A("Aditi Jamsandekar", href="https://www.linkedin.com/in/aditi-jamsandekar-485916301/", target="_blank"),
        ", and ",
        html.A("Siddhi Jani", href="https://www.linkedin.com/in/siddhi-jani-2a0233301/", target="_blank"),
        ", under the mentorship of ",
        html.A("Dr. Sneha Deshmukh", href="https://www.linkedin.com/in/dr-sneha-deshmukh-a7837858/", target="_blank"), " at MPSTME NMIMS University, our tool addresses the increasing need for secure, CIS-compliant configurations in corporate environments.",
        html.A()
    ], className="aboutus_txt"),
    html.P("Our project automates the hardening process for Linux distributions such as Red Hat Enterprise Linux, Rocky Linux, and Oracle Linux. By reducing manual intervention, SecureSys minimizes human error and ensures consistency across distributed systems. The toolkit also includes real-time validation and detailed reporting through an accessible HTML dashboard and downloadable reports, helping enterprises maintain robust cybersecurity and adhere to industry benchmarks.", className="aboutus_txt")
])

@app.callback(
    Output("content", "children"),
    Input("dashboard-link", "n_clicks"),
    Input("resource-link", "n_clicks"),
    Input("about-link", "n_clicks"),
)
def update_content(dashboard_click, resource_click, about_click):
    ctx = dash.callback_context

    if not ctx.triggered:
        return dashboard_content

    button_id = ctx.triggered[0]["prop_id"].split(".")[0]

    if button_id == "resource-link":
        return resource_links_content
    elif button_id == "about-link":
        return about_us_content
    else:
        return dashboard_content

@app.callback(
    Output('details-container', 'children'),
    [Input(f"tile-{module}", "n_clicks") for module in module_data],
    prevent_initial_call=True
)
def display_module_details(*args):
    ctx = dash.callback_context

    if not ctx.triggered:
        return html.Div()

    clicked_module = ctx.triggered[0]['prop_id'].split('.')[0].replace('tile-', '')
    module_failures = module_data[clicked_module]['details']

    return html.Div([
        html.H3(f"Details for {clicked_module}", style={'text-align': 'center'}),
        html.Table([
            html.Tr([html.Th(col) for col in module_failures.columns])
        ] + [
            html.Tr([html.Td(module_failures.iloc[i][col]) for col in module_failures.columns])
            for i in range(len(module_failures))
        ], className="details-table")
    ])


@app.callback(
    Output("search-results", "children"),
    [Input("search-button", "n_clicks"), Input("search-bar", "n_submit")],
    State("search-bar", "value")
)
def update_search_results(n_clicks, n_submit, search_value):
    if (n_clicks == 0 and n_submit is None) or not search_value:
        return [
            html.Div(className="video-item", children=[
                html.Img(src="https://img.youtube.com/vi/Jnxx_IAC0G4/0.jpg", className="video-thumbnail"),
                html.A("10 Tips for Hardening your Linux Servers", href="https://youtu.be/Jnxx_IAC0G4?si=Wfw5DA7PlbakjDmy", target="_blank", className="video-title")
            ]),
            html.Div(className="video-item", children=[
                html.Img(src="https://img.youtube.com/vi/Sa0KqbpLye4/0.jpg", className="video-thumbnail"),
                html.A("The COMPLETE Linux Hardening, Privacy & Security Guide!", href="https://youtu.be/Sa0KqbpLye4?si=JPzydKdz5zkFtBnm", target="_blank", className="video-title")
            ]),
            html.Div(className="video-item", children=[
                html.Img(src="https://img.youtube.com/vi/d2hCS6T1z3k/0.jpg", className="video-thumbnail"),
                html.A("The Ultimate Guide to Linux Hardening: Boost Your System Security [HINDI]", href="https://youtu.be/d2hCS6T1z3k?si=GP7aQcfwolroV72L", target="_blank", className="video-title")
            ]),
            html.Div(className="video-item", children=[
                html.Img(src="https://img.youtube.com/vi/AwrKXtI_tJA/0.jpg", className="video-thumbnail"),
                html.A("Linux Security Hardening - CIS Level1 on RHEL8.7", href="https://youtu.be/AwrKXtI_tJA?si=bc8j6dcEqNXSYvrt", target="_blank", className="video-title")
            ]),
            html.Div(className="video-item", children=[
                html.Img(src="https://img.youtube.com/vi/TVTQcEWMQa0/0.jpg", className="video-thumbnail"),
                html.A("How to Achieve CIS Benchmark Compliance to Harden Linux Systems | Into the Terminal 120", href="https://www.youtube.com/live/TVTQcEWMQa0?si=nyjwmQQfr3TmPEz5", target="_blank", className="video-title")
            ]),
            html.Div(className="video-item", children=[
                html.Img(src="https://img.youtube.com/vi/2orzA98Ih0k/0.jpg", className="video-thumbnail"),
                html.A("What are CIS Benchmarks? and Why are CIS Benchmarks important?", href="https://www.youtube.com/live/2orzA98Ih0k?si=iz6As3tg6dvF4pZV", target="_blank", className="video-title")
            ]),
            html.Div(className="article-item", children=[
                html.H3("Linux System Hardening Checklist", className="article-title"),
                html.P("An extensive checklist for Linux system hardening..."),
                html.A("Read more", href="https://www.cyberciti.biz/tips/linux-security.html", target="_blank", className="read-more-link")
            ]),
            html.Div(className="article-item", children=[
                html.H3("SecureSys", className="article-title"),
                html.P("SecureSys and how it works."),
                html.A("Learn more", href="https://github.com/ChirayuRathi03/SecureSys/blob/5fd74dc114a7a8383bd383be4b1ab67477799786/SecureSys_Universal%20Hardening%20and%20Compliance%20Toolkit.pdf", target="_blank", className="read-more-link")
            ]),
            html.Div(className="article-item", children=[
                html.H3("Server Hardening: Best Practices", className="article-title"),
                html.P("A guide on server hardening with methods to protect..."),
                html.A("Learn more", href="https://www.acunetix.com/blog/articles/server-hardening-best-practices/", target="_blank", className="read-more-link")
            ]), 
            html.Div(className="article-item", children=[
                html.H3("Linux OS Hardening: CIS Benchmarks", className="article-title"),
                html.P("Hardening is a process in which one reduces the vulnerability of resources to prevent it from cyber attacks like Denial of service, unauthorized data access, etc."),
                html.A("Learn more", href="https://opstree.com/blog/2020/04/29/linux-os-hardening-cis-benchmarks/", target="_blank", className="read-more-link")
            ]), 
            html.Div(className="article-item", children=[
                html.H3("Red Hat Enterprise Linux 8 Security hardening", className="article-title"),
                html.P("Learn the processes and practices for securing Red Hat Enterprise Linux servers and workstations against local and remote intrusion, exploitation, and malicious activity. By using these approaches and tools, you can create a more secure computing environment for the data center, workplace, and home."),
                html.A("Learn more", href="https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/pdf/security_hardening/Red_Hat_Enterprise_Linux-8-Security_hardening-en-US.pdf", target="_blank", className="read-more-link")
            ]),
            html.Div(className="article-item", children=[
                html.H3("Red Hat Enterprise Linux 9 Security hardening", className="article-title"),
                html.P("Security begins even before you start the installation of Red Hat Enterprise Linux. Configuring your system securely from the beginning makes it easier to implement additional security settings later."),
                html.A("Learn more", href="https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/pdf/security_hardening/red_hat_enterprise_linux-9-security_hardening-en-us.pdf", target="_blank", className="read-more-link")
            ]),
            html.Div(className="article-item", children=[
                html.H3("Linux Server Hardening and Security Best Practices", className="article-title"),
                html.P("This guide explains how what configuration hardening is and how to establish hardened build standards for your Linux and Unix systems."),
                html.A("Learn more", href="https://www.netwrix.com/linux_hardening_security_best_practices.html#:~:text=Hardening%20a%20system%20means%20optimizing,the%20role%20of%20the%20computer", target="_blank", className="read-more-link")
            ]),
            html.Div(className="article-item", children=[
                html.H3("Windows and Linux Server Hardening: Comprehensive Checklist:", className="article-title"),
                html.P("The Liquid Web blog provides a comprehensive checklist for server hardening, covering key security measures to protect servers from vulnerabilities and cyber threats."),
                html.A("Learn more", href="https://www.liquidweb.com/blog/server-hardening-checklist/", target="_blank", className="read-more-link")
            ]),
        ]

    search_value = search_value.lower()
    resources = [
        {"type": "video", "title": "10 Tips for Hardening your Linux Servers", "link": "https://youtu.be/Jnxx_IAC0G4?si=Wfw5DA7PlbakjDmy", "thumbnail": "https://img.youtube.com/vi/Jnxx_IAC0G4/0.jpg"},
        {"type": "video", "title": "The COMPLETE Linux Hardening, Privacy & Security Guide!", "link": "https://youtu.be/Sa0KqbpLye4?si=JPzydKdz5zkFtBnm", "thumbnail": "https://img.youtube.com/vi/Sa0KqbpLye4/0.jpg"},
        {"type": "video", "title": "The Ultimate Guide to Linux Hardening: Boost Your System Security [HINDI]", "link": "https://youtu.be/d2hCS6T1z3k?si=GP7aQcfwolroV72L", "thumbnail": "https://img.youtube.com/vi/d2hCS6T1z3k/0.jpg"},
        {"type": "video", "title": "Linux Security Hardening - CIS Level1 on RHEL8.7", "link": "https://youtu.be/AwrKXtI_tJA?si=bc8j6dcEqNXSYvrt", "thumbnail": "https://img.youtube.com/vi/AwrKXtI_tJA/0.jpg"},
        {"type": "video", "title": "How to Achieve CIS Benchmark Compliance to Harden Linux Systems | Into the Terminal 120", "link": "https://www.youtube.com/live/TVTQcEWMQa0?si=nyjwmQQfr3TmPEz5", "thumbnail": "https://img.youtube.com/vi/TVTQcEWMQa0/0.jpg"},
        {"type": "video", "title": "What are CIS Benchmarks? and Why are CIS Benchmarks important?", "link": "https://www.youtube.com/live/2orzA98Ih0k?si=iz6As3tg6dvF4pZV", "thumbnail": "https://img.youtube.com/vi/2orzA98Ih0k/0.jpg"},
        {"type": "article", "title": "SecureSys", "link": "https://github.com/ChirayuRathi03/SecureSys/blob/5fd74dc114a7a8383bd383be4b1ab67477799786/SecureSys_Universal%20Hardening%20and%20Compliance%20Toolkit.pdf", "preview": "SecureSys and how it works."},
        {"type": "article", "title": "Linux System Hardening Checklist", "link": "https://www.cyberciti.biz/tips/linux-security.html", "preview": "An extensive checklist for Linux system hardening..."},
        {"type": "article", "title": "Server Hardening: Best Practices", "link": "https://www.acunetix.com/blog/articles/server-hardening-best-practices/", "preview": "A guide on server hardening with methods to protect..."},
        {"type": "article", "title": "Linux OS Hardening: CIS Benchmarks", "link": "https://opstree.com/blog/2020/04/29/linux-os-hardening-cis-benchmarks/", "preview": "Hardening is a process in which one reduces the vulnerability of resources to prevent it from cyber attacks like Denial of service, unauthorized data access, etc."},
        {"type": "article", "title": "Red Hat Enterprise Linux 8 Security hardening", "link": "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/pdf/security_hardening/Red_Hat_Enterprise_Linux-8-Security_hardening-en-US.pdf", "preview": "Learn the processes and practices for securing Red Hat Enterprise Linux servers and workstations against local and remote intrusion, exploitation, and malicious activity. By using these approaches and tools, you can create a more secure computing environment for the data center, workplace, and home."},
        {"type": "article", "title": "Red Hat Enterprise Linux 9 Security hardening", "link": "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/pdf/security_hardening/red_hat_enterprise_linux-9-security_hardening-en-us.pdf", "preview": "Security begins even before you start the installation of Red Hat Enterprise Linux. Configuring your system securely from the beginning makes it easier to implement additional security settings later."},
        {"type": "article", "title": "Linux Server Hardening and Security Best Practices", "link": "https://www.netwrix.com/linux_hardening_security_best_practices.html#:~:text=Hardening%20a%20system%20means%20optimizing,the%20role%20of%20the%20computer", "preview": "This guide explains how what configuration hardening is and how to establish hardened build standards for your Linux and Unix systems."},
        {"type": "article", "title": "Windows and Linux Server Hardening: Comprehensive Checklist:", "link": "https://www.liquidweb.com/blog/server-hardening-checklist/", "preview": "The Liquid Web blog provides a comprehensive checklist for server hardening, covering key security measures to protect servers from vulnerabilities and cyber threats."},
    ]

    filtered_resources = [res for res in resources if search_value in res["title"].lower()]

    children = []
    for res in filtered_resources:
        if res["type"] == "video":
            children.append(html.Div(className="video-item", children=[
                html.Img(src=res["thumbnail"], className="video-thumbnail"),
                html.A(res["title"], href=res["link"], target="_blank", className="video-title")
            ]))
        elif res["type"] == "article":
            children.append(html.Div(className="article-item", children=[
                html.H3(res["title"], className="article-title"),
                html.P(res["preview"]),
                html.A("Read more", href=res["link"], target="_blank", className="read-more-link")
            ]))
    
    return children

@server.route("/download_pdf")
def download_pdf():
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    max_width = width - 100

    p.setFont("Helvetica-Bold", 16)
    p.drawString(30, height - 40, "SecureSys Dashboard Report")

    p.setFont("Helvetica", 12)
    p.drawString(30, height - 70, f"Total Success: {total_success}")
    p.drawString(30, height - 90, f"Total Failure: {total_failure}")

    pie_chart_image = generate_pie_chart_image()
    p.drawImage(pie_chart_image, 30, height - 550, width=300, height=300)

    y = height - 580
    p.setFont("Helvetica-Bold", 14)
    p.drawString(30, y, "Failed Items by Module")
    y -= 20

    for module, data in module_data.items():
        if data['failures'] > 0:
            if y < 50:
                p.showPage()
                y = height - 40
            
            p.setFont("Helvetica-Bold", 12)
            p.drawString(30, y, f"Module: {module}")
            y -= 15
            p.setFont("Helvetica", 10)
            
            for idx, row in data['details'].iterrows():
                if y < 50:
                    p.showPage()
                    y = height - 40
                    p.setFont("Helvetica-Bold", 12)
                    p.drawString(30, y, f"Module: {module}")
                    y -= 15
                    p.setFont("Helvetica", 10)
                
                y = wrap_text(f"Expected: {row['Expected Output']}", max_width, p, 50, y)
                y = wrap_text(f"Actual: {row['Actual Output']}", max_width, p, 50, y)
                y -= 5

            y -= 10

    p.save()
    buffer.seek(0)

    return send_file(buffer, as_attachment=True, download_name="SecureSys_Report.pdf", mimetype="application/pdf")

def wrap_text(text, width, canvas, x, y, line_height=12):
    wrapped_text = text.split('\n')
    for line in wrapped_text:
        if y < 50:
            canvas.showPage()
            y = letter[1] - 40
        canvas.drawString(x, y, line)
        y -= line_height
    return y

if __name__ == '__main__':
    app.run_server(debug=True)
