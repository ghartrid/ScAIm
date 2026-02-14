/**
 * ScAIm Keyword Configuration
 * Categorized keyword lists with suspicion weights (1-10).
 * Higher weight = more suspicious when found on a page.
 */
const SCAIM_KEYWORDS = {
  financial: {
    label: "Financial",
    keywords: [
      { term: "financial", weight: 4 },
      { term: "bank account", weight: 6 },
      { term: "wire transfer", weight: 7 },
      { term: "credit card", weight: 5 },
      { term: "debit card", weight: 5 },
      { term: "payment", weight: 3 },
      { term: "billing", weight: 3 },
      { term: "invest", weight: 4 },
      { term: "cryptocurrency", weight: 5 },
      { term: "crypto wallet", weight: 6 },
      { term: "wallet", weight: 4 },
      { term: "routing number", weight: 8 },
      { term: "IBAN", weight: 7 },
      { term: "account number", weight: 7 },
      { term: "bank details", weight: 7 },
      { term: "swift code", weight: 6 },
      { term: "PayPal", weight: 3 },
      { term: "Venmo", weight: 3 },
      { term: "Zelle", weight: 3 },
      { term: "Western Union", weight: 6 },
      { term: "money order", weight: 5 },
      { term: "gift card", weight: 5 },
      { term: "bitcoin", weight: 4 },
      { term: "ethereum", weight: 4 }
    ]
  },

  money: {
    label: "Money/Transaction",
    keywords: [
      { term: "money", weight: 3 },
      { term: "send funds", weight: 6 },
      { term: "transfer funds", weight: 6 },
      { term: "deposit", weight: 4 },
      { term: "withdraw", weight: 4 },
      { term: "withdrawal", weight: 4 },
      { term: "transaction", weight: 3 },
      { term: "fee", weight: 3 },
      { term: "charge", weight: 3 },
      { term: "refund", weight: 4 },
      { term: "cashback", weight: 3 },
      { term: "payout", weight: 5 },
      { term: "processing fee", weight: 5 },
      { term: "advance fee", weight: 7 },
      { term: "upfront payment", weight: 6 },
      { term: "minimum deposit", weight: 5 },
      { term: "guaranteed return", weight: 7 },
      { term: "double your money", weight: 9 },
      { term: "risk-free", weight: 6 }
    ]
  },

  dataExchange: {
    label: "Data Exchange",
    keywords: [
      { term: "user data", weight: 5 },
      { term: "personal information", weight: 6 },
      { term: "social security", weight: 9 },
      { term: "SSN", weight: 9 },
      { term: "date of birth", weight: 6 },
      { term: "mother's maiden name", weight: 8 },
      { term: "exchange info", weight: 5 },
      { term: "share your details", weight: 7 },
      { term: "verify identity", weight: 7 },
      { term: "confirm your account", weight: 6 },
      { term: "upload ID", weight: 8 },
      { term: "passport", weight: 6 },
      { term: "driver's license", weight: 6 },
      { term: "tax ID", weight: 7 },
      { term: "login credentials", weight: 8 },
      { term: "password", weight: 4 },
      { term: "PIN", weight: 5 },
      { term: "security question", weight: 5 },
      { term: "verify your email", weight: 4 },
      { term: "confirm your identity", weight: 7 },
      { term: "update your information", weight: 5 },
      { term: "provide your details", weight: 6 }
    ]
  },

  urgency: {
    label: "Urgency",
    isMultiplier: true,
    keywords: [
      { term: "immediately", weight: 5 },
      { term: "act now", weight: 7 },
      { term: "expires", weight: 4 },
      { term: "limited time", weight: 5 },
      { term: "suspended", weight: 6 },
      { term: "urgent", weight: 6 },
      { term: "final warning", weight: 8 },
      { term: "account locked", weight: 7 },
      { term: "within 24 hours", weight: 7 },
      { term: "within 48 hours", weight: 6 },
      { term: "don't delay", weight: 5 },
      { term: "time is running out", weight: 7 },
      { term: "last chance", weight: 6 },
      { term: "respond immediately", weight: 8 },
      { term: "failure to comply", weight: 8 },
      { term: "action required", weight: 5 },
      { term: "immediate action", weight: 7 },
      { term: "your account will be", weight: 6 },
      { term: "unauthorized activity", weight: 7 },
      { term: "suspicious activity detected", weight: 6 }
    ]
  },

  authority: {
    label: "Authority Impersonation",
    keywords: [
      { term: "IRS", weight: 5 },
      { term: "FBI", weight: 5 },
      { term: "CIA", weight: 5 },
      { term: "Microsoft Support", weight: 7 },
      { term: "Apple Security", weight: 7 },
      { term: "Google Security", weight: 7 },
      { term: "Amazon Security", weight: 7 },
      { term: "your bank", weight: 5 },
      { term: "law enforcement", weight: 6 },
      { term: "legal action", weight: 6 },
      { term: "court order", weight: 7 },
      { term: "federal agency", weight: 6 },
      { term: "tax authority", weight: 5 },
      { term: "government agency", weight: 5 },
      { term: "official notice", weight: 6 },
      { term: "compliance department", weight: 5 },
      { term: "security team", weight: 4 },
      { term: "fraud department", weight: 5 },
      { term: "technical support", weight: 4 }
    ]
  },

  rewardBait: {
    label: "Reward Bait",
    keywords: [
      { term: "congratulations", weight: 4 },
      { term: "you've won", weight: 7 },
      { term: "you have won", weight: 7 },
      { term: "you are a winner", weight: 8 },
      { term: "free gift", weight: 5 },
      { term: "claim your prize", weight: 8 },
      { term: "selected winner", weight: 8 },
      { term: "exclusive offer", weight: 4 },
      { term: "you've been selected", weight: 7 },
      { term: "you have been chosen", weight: 7 },
      { term: "lucky visitor", weight: 9 },
      { term: "one millionth visitor", weight: 9 },
      { term: "spin the wheel", weight: 7 },
      { term: "claim now", weight: 6 },
      { term: "free trial", weight: 3 },
      { term: "no cost", weight: 3 },
      { term: "100% free", weight: 5 }
    ]
  },

  crypto: {
    label: "Crypto/Investment",
    keywords: [
      { term: "HODL", weight: 3 },
      { term: "to the moon", weight: 4 },
      { term: "diamond hands", weight: 3 },
      { term: "NFT mint", weight: 4 },
      { term: "airdrop", weight: 4 },
      { term: "seed phrase", weight: 9 },
      { term: "recovery phrase", weight: 8 },
      { term: "private key", weight: 7 },
      { term: "connect wallet", weight: 5 },
      { term: "DeFi", weight: 3 },
      { term: "yield farming", weight: 4 },
      { term: "staking rewards", weight: 4 },
      { term: "liquidity pool", weight: 4 },
      { term: "token presale", weight: 6 },
      { term: "whitelist spot", weight: 5 },
      { term: "rug pull", weight: 7 },
      { term: "pump and dump", weight: 8 },
      { term: "guaranteed profit", weight: 8 },
      { term: "passive income", weight: 5 },
      { term: "trading bot", weight: 5 },
      { term: "mining contract", weight: 5 },
      { term: "double your crypto", weight: 9 },
      { term: "send ETH", weight: 7 },
      { term: "send BTC", weight: 7 }
    ]
  }
};
