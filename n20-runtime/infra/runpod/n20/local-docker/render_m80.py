"""Render the synthetic local M80 pilot results as SVG and PNG."""
from __future__ import annotations
import csv
from pathlib import Path
import sys

import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt


def read(path):
    with path.open(encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def render(root):
    curves, events = read(root/"ema_by_round.csv"), read(root/"events.csv")
    if len(curves) != 51 or len(events) != 50:
        raise ValueError("Incomplete result for rendering.")
    fig, (ax, lower) = plt.subplots(2,1,figsize=(12,7.2),sharex=True,height_ratios=[2.1,1.2])
    fig.subplots_adjust(left=.095,right=.97,top=.803,bottom=.14,hspace=.17)
    for a in (ax,lower):
        a.spines[["top","right"]].set_visible(False)
        a.axvspan(.5,3.5,color="#f2cc75",alpha=.43)
        a.grid(axis="y",alpha=.22)
        a.set_axisbelow(True)
        for event in events:
            if event["phase"]=="audit":
                a.axvline(int(event["round"]),color="#007c91",alpha=.24,linewidth=1.3)
    rs=[int(x["round"]) for x in curves]
    for key,color,style,label in (
        ("slow_honest","#185fa7","-","Honestos • EMA slow-up"),
        ("slow_malicious","#c34726","-","Conluio • EMA slow-up"),
        ("symmetric_honest","#185fa7","--","Honestos • EMA simétrico (replay)"),
        ("symmetric_malicious","#c34726","--","Conluio • EMA simétrico (replay)"),
    ):
        ax.plot(rs,[float(x[key]) for x in curves],style,color=color,label=label,linewidth=2.0)
    ax.set_ylim(0,1.04)
    ax.set_ylabel("Reputação média")
    handles, labels = ax.get_legend_handles_labels()
    fig.legend(handles,labels,loc="upper left",bbox_to_anchor=(.089,.86),ncol=4,frameon=False,fontsize=8.5)
    lower.bar([int(x["round"]) for x in events], [int(x["absent_malicious"]) for x in events],
              color="#7d64ad",width=.72,label="Respostas ausentes (só nós instáveis)")
    accepted=[int(x["round"]) for x in events if x["quorum_outcome"]=="accepted"]
    fixed=[int(x["round"]) for x in events if x["phase"]=="test"]
    lower.scatter(accepted,[15]*len(accepted),s=11,c="#257b54",marker="o",label="Quórum aceitou (grupo de referência)")
    lower.scatter(fixed,[-.4]*len(fixed),s=27,c="#d34b30",marker="v",clip_on=False,label="Rodada de teste (não auditada)")
    lower.set_yticks([0,4,8,12,16])
    lower.set_ylim(0,17)
    lower.set_ylabel("Nós ausentes")
    lower.set_xlabel("Rodada • 0 = reputação inicial")
    lower.set_xticks([0,5,10,15,20,25,30,35,40,45,50])
    lower.set_xlim(0,51)
    lower.legend(loc="upper left",bbox_to_anchor=(0,-.31),ncol=3,frameon=False,fontsize=8)
    fig.suptitle("Evolução da reputação e eventos do protocolo", x=.09, y=.965, ha="left",fontsize=20,fontweight="bold")
    fig.text(.095,.905,"Piloto CPU simulado · 20 nós · 50 rodadas · 80% em conluio/instáveis · semente 0",fontsize=11,color="#42475a")
    fig.text(.095,.881,"Faixa amarela: gênese sem quórum (1–3). Linhas verticais azuis: auditorias sorteadas (p=0,2).",fontsize=9,color="#42475a")
    for extension in ("png","svg"):
        target=root/f"ema-eventos-final.{extension}"
        if target.exists():
            raise FileExistsError("Refusing to replace graph.")
        if extension=="svg":
            fig.savefig(target,metadata={"Date":None})
        else:
            fig.savefig(target,dpi=135)
    plt.close(fig)


if __name__=="__main__":
    render(Path(sys.argv[1]))
