import streamlit as st
import pandas as pd
import re

st.set_page_config(page_title="Threat Intelligence Dashboard", layout="wide")

st.markdown("""
<style>
.stApp {
    background-color: #0f172a;
    color: white;
}

.title {
    color: #38bdf8;
    font-size: 38px;
    font-weight: 700;
}

.small-text {
    color: #cbd5e1;
}

.box {
    background-color: #111827;
    padding: 18px;
    border-radius: 10px;
    border: 1px solid #334155;
}

.high {
    border-left: 5px solid #ef4444;
}

.medium {
    border-left: 5px solid #f59e0b;
}

.low {
    border-left: 5px solid #22c55e;
}

.stButton button {
    background-color: #0284c7;
    color: white;
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)


def get_type(value):
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", value):
        return "IP Address"

    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "MD5 Hash"

    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "SHA1 Hash"

    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "SHA256 Hash"

    if "." in value:
        return "Domain"

    return "Unknown"


def get_risk(value, ioc_type):
    score = 10
    notes = []

    words = ["login", "secure", "verify", "paypal", "bank", "alert", "update"]

    if ioc_type == "Domain":
        for word in words:
            if word in value.lower():
                score += 20
                notes.append("Suspicious word found: " + word)

        if "-" in value:
            score += 15
            notes.append("Domain contains a hyphen")

        if value.endswith(".xyz") or value.endswith(".ru"):
            score += 20
            notes.append("Suspicious domain extension")

    elif ioc_type == "IP Address":
        if value.startswith("192.168.") or value.startswith("10."):
            notes.append("Private IP address")
        else:
            score += 15
            notes.append("Public IP address")

    elif "Hash" in ioc_type:
        score += 10
        notes.append("File hash detected")

    if score >= 60:
        risk = "High"
    elif score >= 30:
        risk = "Medium"
    else:
        risk = "Low"

    if len(notes) == 0:
        notes.append("No obvious suspicious indicators found")

    return risk, score, notes


st.markdown('<div class="title">Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
st.markdown(
    '<p class="small-text">Simple SOC-style tool for checking IPs, domains and hashes.</p>',
    unsafe_allow_html=True
)

iocs_text = st.text_area(
    "Enter IOCs, one per line",
    height=140,
    placeholder="8.8.8.8\npaypal-security-alert.xyz\n44d88612fea8a8f36de82e1278abb02f"
)

if st.button("Analyze"):
    lines = iocs_text.splitlines()
    results = []

    for line in lines:
        ioc = line.strip()

        if ioc == "":
            continue

        ioc_type = get_type(ioc)
        risk, score, notes = get_risk(ioc, ioc_type)

        results.append({
            "IOC": ioc,
            "Type": ioc_type,
            "Risk": risk,
            "Score": score,
            "Notes": notes
        })

    if len(results) == 0:
        st.warning("Please enter at least one IOC.")
    else:
        df = pd.DataFrame(results)

        st.subheader("Overview")

        high = len(df[df["Risk"] == "High"])
        medium = len(df[df["Risk"] == "Medium"])
        low = len(df[df["Risk"] == "Low"])

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Total IOCs", len(df))
        c2.metric("High Risk", high)
        c3.metric("Medium Risk", medium)
        c4.metric("Low Risk", low)

        st.subheader("IOC Table")
        st.dataframe(
            df[["IOC", "Type", "Risk", "Score"]],
            width="stretch"
        )

        st.subheader("Detailed Analysis")

        for item in results:
            color_class = item["Risk"].lower()

            notes_html = ""
            for note in item["Notes"]:
                notes_html += "<li>" + note + "</li>"

            st.markdown(f"""
            <div class="box {color_class}">
                <b>{item["IOC"]}</b><br>
                Type: {item["Type"]}<br>
                Risk: {item["Risk"]}<br>
                Score: {item["Score"]}/100<br><br>
                <b>Notes:</b>
                <ul>
                    {notes_html}
                </ul>
            </div>
            <br>
            """, unsafe_allow_html=True)