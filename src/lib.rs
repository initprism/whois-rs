#[macro_use] extern crate serde;

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;
use anyhow::Result;

const SERVER: &'static str = include_str!("../server.json");

#[derive(Debug, Deserialize, Serialize, PartialEq, Clone)]
pub struct WhoIs {
    pub domain: String,
    pub expiration_date: Option<DateTime<Utc>>,
    pub is_registered: bool,
    pub is_under_grace_period: bool,
}

impl WhoIs {
    pub async fn lookup (domain: &str) -> Result<Self> {
        let whois = whois_rust::WhoIs::from_string(SERVER)?;
        let options = whois_rust::WhoIsLookupOptions::from_str(domain)?;

        let text = whois.lookup_async(options).await?;
        Ok(Self::parse(domain, &text))
    }

    fn parse(domain: &str, text: &str) -> Self {
        let mut whois = Self {
            domain: String::from(domain),
            expiration_date: None,
            is_registered: false,
            is_under_grace_period: false,
        };

        let lines = text.lines();
        for line in lines {
            let line_trimmed = line.trim();

            // Determine if domain is registered
            if line_trimmed.starts_with("Domain not found.")
                || line_trimmed.starts_with("Domain not registered.")
                || line_trimmed.starts_with("No match for")
                || line_trimmed.starts_with("% No entries found for query")
            {
                break;
            }

            // Parse expiration date
            if line_trimmed.starts_with("Registry Expiry Date:") {
                if let Ok(re) = Regex::new(r"Registry Expiry Date:\s+(.*)") {
                    for caps in re.captures_iter(line_trimmed) {
                        if let Some(result) = caps.get(1) {
                            whois.is_registered = true;
                            whois.expiration_date = result.as_str().parse::<DateTime<Utc>>().ok();
                        }
                    }
                }
                
                continue;
            } else if line_trimmed.starts_with("Expiry date:") {
                if let Ok(re) = Regex::new(r"Expiry date:\s+(.*)") {
                    for caps in re.captures_iter(line_trimmed) {
                        if let Some(result) = caps.get(1) {
                            if let Ok(naive_date) = NaiveDate::parse_from_str(result.as_str(), "%d-%B-%Y") {
                                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                                whois.is_registered = true;
                                whois.expiration_date = Some(DateTime::<Utc>::from_utc(naive_datetime, Utc));
                            }
                        } 
                    }
                }
                continue;
            } else if line_trimmed.starts_with("expires:") {
                if let Ok(re) = Regex::new(r"expires:\s+(.*)") {
                    for caps in re.captures_iter(line_trimmed) {
                        if let Some(result) = caps.get(1) {
                            if let Ok(naive_date) = NaiveDate::parse_from_str(result.as_str(), "%B %d %Y") {
                                let naive_datetime: NaiveDateTime = naive_date.and_hms(0, 0, 0);
                                whois.is_registered = true;
                                whois.expiration_date = Some(DateTime::<Utc>::from_utc(naive_datetime, Utc));
                            }
                        }
                    }
                }

                
                continue;
            } else if line_trimmed.starts_with("Expiration date:") {
                if let Ok(re) = Regex::new(r"Expiration date:\s+(.*)") {
                    for caps in re.captures_iter(line_trimmed) {
                        if let Some(result) = caps.get(1) {
                            if let Ok(naive_datetime) =  NaiveDateTime::parse_from_str(
                                result.as_str(),
                                "%d.%m.%Y %H:%M:%S",
                            ) {
                                whois.is_registered = true;
                                whois.expiration_date = Some(DateTime::<Utc>::from_utc(naive_datetime, Utc));
                            }
                        }
                    }
                }
                continue;
            }

            // Parse status
            if line_trimmed.starts_with("Domain Status:") {
                if let Ok(re) = Regex::new(r"Domain Status:\s+(.*)") {
                    for caps in re.captures_iter(line_trimmed) {
                        if let Some(result) = caps.get(1) {
                            if result.as_str() == "redemptionPeriod https://icann.org/epp#redemptionPeriod" {
                                whois.is_under_grace_period = true;
                            }
                        }
                    }
                }
                continue;
            }
        }
        whois
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[test]
    fn test_whois() {
        let whois = aw!(WhoIs::lookup("monitorapp.com")).unwrap();
        println!("{:#?}", whois);
        assert!(whois.is_registered);
    }
}