# -*- coding: utf-8 -*-
# gmcp/plot_style.py

import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.ticker import PercentFormatter


ACADEMIC_COLORS = [
    "#2F5597",
    "#C55A11",
    "#548235",
    "#8064A2",
    "#1F7A8C",
    "#7F6000",
    "#A23E48",
    "#4B6584",
]

PROTOCOL_LABELS = {
    "seq_mac": "序号+MAC",
    "hash_chain": "哈希链",
    "ticket_only": "会话票据",
    "gmcp_r": "GMCP-R",
}

ATTACK_LABELS = {
    "none": "正常通信",
    "drop": "丢包",
    "modify": "篡改",
    "replay": "重放",
    "prev_mem": "记忆断裂",
    "rollback_ticket": "票据回滚",
    "disconnect": "断连",
    "network_loss": "网络丢包",
    "forge_snack": "伪造SNACK",
    "forge_ir_refresh": "伪造IR刷新",
}

TICKET_LABELS = {
    "valid_ticket": "有效票据",
    "expired_ticket": "过期票据",
    "replayed_ticket": "重放票据",
    "tampered_ticket": "篡改票据",
    "wrong_session_ticket": "错误会话票据",
    "rollback_ticket": "回滚票据",
}


def setup_chinese_academic_style():
    preferred_fonts = [
        "PingFang SC",
        "Hiragino Sans GB",
        "Heiti SC",
        "STHeiti",
        "Songti SC",
        "Microsoft YaHei",
        "SimHei",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
        "WenQuanYi Micro Hei",
        "Arial Unicode MS",
    ]
    available_fonts = set(f.name for f in font_manager.fontManager.ttflist)
    chosen_fonts = [name for name in preferred_fonts if name in available_fonts]
    if not chosen_fonts:
        chosen_fonts = ["DejaVu Sans"]

    plt.rcParams.update(
        {
            "font.sans-serif": chosen_fonts + ["DejaVu Sans"],
            "axes.unicode_minus": False,
            "figure.dpi": 160,
            "savefig.dpi": 300,
            "savefig.facecolor": "white",
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "axes.edgecolor": "#333333",
            "axes.linewidth": 0.8,
            "axes.titlesize": 14,
            "axes.titleweight": "bold",
            "axes.labelsize": 12,
            "xtick.labelsize": 10,
            "ytick.labelsize": 10,
            "legend.fontsize": 10,
            "lines.linewidth": 2.2,
            "lines.markersize": 5.5,
        }
    )


def localize_value(value):
    text = str(value)
    if text in PROTOCOL_LABELS:
        return PROTOCOL_LABELS[text]
    if text in ATTACK_LABELS:
        return ATTACK_LABELS[text]
    if text in TICKET_LABELS:
        return TICKET_LABELS[text]
    return value


def localize_index(series):
    localized = series.copy()
    localized.index = [localize_value(value) for value in localized.index]
    return localized


def localize_columns(table):
    localized = table.copy()
    localized.columns = [localize_value(value) for value in localized.columns]
    return localized


def style_axes(ax, rate_axis=False):
    ax.set_axisbelow(True)
    ax.grid(axis="y", color="#D9DEE7", linestyle="--", linewidth=0.7, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#555555")
    ax.spines["bottom"].set_color("#555555")
    if rate_axis:
        ax.set_ylim(0, 1.05)
        ax.yaxis.set_major_formatter(PercentFormatter(xmax=1.0))


def is_rate_like(series_or_table):
    try:
        values = series_or_table.values.flatten()
    except AttributeError:
        values = series_or_table.values
    numeric_values = [float(value) for value in values if str(value) != "nan"]
    return bool(numeric_values) and min(numeric_values) >= 0 and max(numeric_values) <= 1.05


def save_bar_chart(series, xlabel, ylabel, title, output_path, rotation=45, figsize=(8, 5)):
    setup_chinese_academic_style()
    data = localize_index(series)
    colors = [ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)] for i in range(len(data))]
    fig, ax = plt.subplots(figsize=figsize)
    data.plot(
        kind="bar",
        ax=ax,
        color=colors,
        edgecolor="#2D3748",
        linewidth=0.7,
        width=0.68,
    )
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, pad=14)
    ax.tick_params(axis="x", rotation=rotation)
    style_axes(ax, rate_axis=is_rate_like(data))
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)


def save_line_chart(table, xlabel, ylabel, title, output_path, figsize=(8, 5)):
    setup_chinese_academic_style()
    data = localize_columns(table)
    fig, ax = plt.subplots(figsize=figsize)
    data.plot(
        kind="line",
        ax=ax,
        marker="o",
        color=[ACADEMIC_COLORS[i % len(ACADEMIC_COLORS)] for i in range(len(data.columns))],
    )
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title, pad=14)
    style_axes(ax, rate_axis=is_rate_like(data))
    legend = ax.get_legend()
    if legend is not None:
        legend.set_frame_on(False)
    fig.tight_layout()
    fig.savefig(output_path, bbox_inches="tight")
    plt.close(fig)
