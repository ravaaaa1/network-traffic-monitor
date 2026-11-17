"""First-year return on investment for the TechnoProfi scenario."""

import json
from dataclasses import asdict, dataclass, replace
from math import isfinite


@dataclass(frozen=True)
class Scenario:
    annual_hours: float = 8760
    baseline_downtime_hours: float = 60
    downtime_reduction: float = 0.60
    downtime_cost_per_hour: float = 1000
    ponemon_breach_cost: float = 4_990_000
    local_direct_cost_share: float = 0.20
    annual_probability: float = 0.10
    leakage_loss_reduction: float = 0.20
    implementation_cost: float = 25_000
    annual_operating_cost: float = 15_000


def calculate(scenario):
    values = asdict(scenario)
    if any(type(x) not in (int, float) or not isfinite(x) or x < 0 for x in values.values()):
        raise ValueError("Ожидаются конечные неотрицательные числа")
    rates = (scenario.downtime_reduction, scenario.local_direct_cost_share,
             scenario.annual_probability, scenario.leakage_loss_reduction)
    cost = scenario.implementation_cost + scenario.annual_operating_cost
    if max(rates) > 1 or not 0 <= scenario.baseline_downtime_hours <= scenario.annual_hours:
        raise ValueError("Проверьте доли и часы простоя")
    if scenario.annual_hours == 0 or cost == 0:
        raise ValueError("Период расчёта и стоимость должны быть положительными")

    hours_saved = scenario.baseline_downtime_hours * scenario.downtime_reduction
    after = scenario.baseline_downtime_hours - hours_saved
    downtime_savings = hours_saved * scenario.downtime_cost_per_hour
    local_direct_cost = scenario.ponemon_breach_cost * scenario.local_direct_cost_share
    expected_leakage_loss = local_direct_cost * scenario.annual_probability
    leakage_savings = expected_leakage_loss * scenario.leakage_loss_reduction
    benefit = downtime_savings + leakage_savings
    operating_savings = benefit - scenario.annual_operating_cost
    return {
        "after_downtime_hours": round(after, 2), "saved_hours": round(hours_saved, 2),
        "availability_before_percent": round(100 * (1 - scenario.baseline_downtime_hours / scenario.annual_hours), 4),
        "availability_after_percent": round(100 * (1 - after / scenario.annual_hours), 4),
        "downtime_savings_usd": round(downtime_savings, 2),
        "direct_breach_cost_usd": round(local_direct_cost, 2),
        "expected_leakage_loss_before_usd": round(expected_leakage_loss, 2),
        "expected_leakage_loss_after_usd": round(expected_leakage_loss - leakage_savings, 2),
        "leakage_savings_usd": round(leakage_savings, 2),
        "benefit_usd": round(benefit, 2), "first_year_cost_usd": round(cost, 2),
        "net_benefit_usd": round(benefit - cost, 2),
        "first_year_roi_percent": round(100 * (benefit - cost) / cost, 2),
        "simple_payback_months": round(12 * scenario.implementation_cost / operating_savings, 2)
        if operating_savings > 0 else None,
    }


def run_roi(path=None):
    if path:
        try:
            base = Scenario(**json.loads(path.read_text(encoding="utf-8-sig")))
        except TypeError as error:
            raise ValueError("Некорректные параметры сценария ROI") from error
    else:
        base = Scenario()
    return {
        "assumptions": asdict(base),
        "base": calculate(base),
        "conservative": calculate(replace(
            base, downtime_reduction=base.downtime_reduction * 0.5,
            leakage_loss_reduction=base.leakage_loss_reduction * 0.5,
        )),
        "optimistic": calculate(replace(
            base, downtime_reduction=min(1, base.downtime_reduction * 1.25),
            leakage_loss_reduction=min(1, base.leakage_loss_reduction * 1.5),
        )),
    }
