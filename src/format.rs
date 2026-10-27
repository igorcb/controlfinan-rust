//! Formatting that matches Rails' pt-BR helpers (number_to_currency, l(date)) and BigDecimal#to_s.

use chrono::NaiveDate;
use rust_decimal::{Decimal, RoundingStrategy};

pub const MONTHS: [&str; 12] = [
    "janeiro",
    "fevereiro",
    "março",
    "abril",
    "maio",
    "junho",
    "julho",
    "agosto",
    "setembro",
    "outubro",
    "novembro",
    "dezembro",
];

/// "R$ 1.234,50"; negatives as "-R$ 1.234,50".
pub fn currency(value: Decimal) -> String {
    let amount = value.round_dp_with_strategy(2, RoundingStrategy::MidpointAwayFromZero);
    let sign = if amount.is_sign_negative() && !amount.is_zero() {
        "-"
    } else {
        ""
    };
    let text = format!("{:.2}", amount.abs());
    let (units, cents) = text.split_once('.').unwrap_or((&text, "00"));
    let mut grouped = String::new();
    for (i, digit) in units.chars().enumerate() {
        if i > 0 && (units.len() - i) % 3 == 0 {
            grouped.push('.');
        }
        grouped.push(digit);
    }
    format!("{sign}R$ {grouped},{cents}")
}

/// The color of an amount: red when negative, green otherwise.
pub fn amount_class(value: Decimal) -> &'static str {
    if value.is_sign_negative() && !value.is_zero() {
        "text-red-700"
    } else {
        "text-emerald-700"
    }
}

/// How Ruby prints a BigDecimal: 150 -> "150.0", 12.50 -> "12.5".
pub fn decimal_text(value: Decimal) -> String {
    let text = value.normalize().to_string();
    if text.contains('.') {
        text
    } else {
        format!("{text}.0")
    }
}

pub fn br_date(date: NaiveDate) -> String {
    date.format("%d/%m/%Y").to_string()
}

pub fn day_month(date: NaiveDate) -> String {
    date.format("%d/%m").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn d(text: &str) -> Decimal {
        Decimal::from_str(text).unwrap()
    }

    #[test]
    fn currency_formats_like_rails_in_portuguese() {
        assert_eq!(currency(d("1234.5")), "R$ 1.234,50");
        assert_eq!(currency(d("-12.5")), "-R$ 12,50");
        assert_eq!(currency(d("0")), "R$ 0,00");
        assert_eq!(currency(d("-0.00")), "R$ 0,00");
        assert_eq!(currency(d("1234567.89")), "R$ 1.234.567,89");
    }

    #[test]
    fn decimal_text_prints_like_ruby_big_decimal() {
        assert_eq!(decimal_text(d("150.00")), "150.0");
        assert_eq!(decimal_text(d("12.50")), "12.5");
        assert_eq!(decimal_text(d("0.05")), "0.05");
        assert_eq!(decimal_text(d("0.00")), "0.0");
    }

    #[test]
    fn amount_class_is_red_only_for_negative_amounts() {
        assert_eq!(amount_class(d("-1")), "text-red-700");
        assert_eq!(amount_class(d("-0.00")), "text-emerald-700");
        assert_eq!(amount_class(d("1")), "text-emerald-700");
    }
}
