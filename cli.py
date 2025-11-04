#!/usr/bin/env python3
import click
from ioc_collector import collect_from_file, save_csv
from ioc_enricher import enrich_batch, save_csv as save_enriched_csv
from ai_model import train, predict
from report_gen import generate_reports
from pathlib import Path
import csv, os

@click.group()
def cli():
    pass

@cli.command()
@click.argument('file')
@click.option('--out', default='data/normalized_iocs.csv')
def collect(file, out):
    recs = collect_from_file(file)
    save_csv(recs, out)
    click.echo(f"Saved {len(recs)} normalized IOCs -> {out}")

@cli.command()
@click.argument('file')
@click.option('--out', default='data/enriched_iocs.csv')
def enrich(file, out):
    recs = []
    p = Path(file)
    if p.suffix.lower() == '.csv' and p.exists():
        with p.open() as f:
            r = csv.DictReader(f)
            recs = [row for row in r]
    else:
        recs = collect_from_file(file)
    enriched = enrich_batch(recs)
    save_enriched_csv(enriched, out)
    click.echo(f"Saved {len(enriched)} enriched IOCs -> {out}")

@cli.command()
@click.argument('file')
@click.option('--model', default=os.getenv('MODEL_PATH', 'models/risk_predictor.pkl'))
@click.option('--out', default='data/predicted_iocs.csv')
def predict_cmd(file, model, out):
    predict(file, model, out)

@cli.command()
@click.argument('file')
def report(file):
    generate_reports(file)

@cli.command()
@click.option('--data', default='data/training_iocs.csv')
@click.option('--out', default=os.getenv('MODEL_PATH', 'models/risk_predictor.pkl'))
def train_cmd(data, out):
    train(data, out)

if __name__ == '__main__':
    cli()
