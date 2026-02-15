/**
 * ScAIm Social Media Post Scanner
 * Scans individual posts/articles on social media feeds for scam indicators.
 * Injects inline warnings directly on suspicious posts instead of relying
 * on the page-level banner (which gets diluted by legitimate content).
 *
 * Designed to be NEUROTIC on social media — Facebook, Instagram, etc. are
 * major scam vectors. Some false positives are acceptable and expected.
 */
const SocialMediaScanner = {
  _platform: null,
  _observer: null,
  _scannedPosts: new WeakSet(),
  _enabled: true,

  // Platform configurations: hostname patterns → post container selectors
  PLATFORMS: {
    facebook: {
      hosts: ["facebook.com", "www.facebook.com", "m.facebook.com", "web.facebook.com"],
      postSelector: '[role="article"]',
      feedSelector: '[role="feed"], [role="main"]',
      linkSelector: 'a[href]',
      paranoia: "high"  // Extra neurotic on Facebook
    },
    x: {
      hosts: ["x.com", "www.x.com", "twitter.com", "www.twitter.com"],
      postSelector: 'article, [data-testid="tweet"]',
      feedSelector: '[aria-label*="Timeline"], [data-testid="primaryColumn"], main',
      linkSelector: 'a[href]',
      paranoia: "high",
      // X wraps ALL external links through t.co — don't flag those as shorteners
      ownShortener: "t.co"
    },
    instagram: {
      hosts: ["instagram.com", "www.instagram.com"],
      postSelector: 'article',
      feedSelector: 'main',
      linkSelector: 'a[href]',
      paranoia: "high"
    },
    linkedin: {
      hosts: ["linkedin.com", "www.linkedin.com"],
      postSelector: '.feed-shared-update-v2, .occludable-update, [data-urn]',
      feedSelector: '.scaffold-finite-scroll, main',
      linkSelector: 'a[href]',
      paranoia: "medium"
    },
    reddit: {
      hosts: ["reddit.com", "www.reddit.com", "old.reddit.com", "new.reddit.com"],
      postSelector: '[data-testid="post-container"], shreddit-post, .thing.link',
      feedSelector: '[data-testid="posts-list"], .siteTable, main',
      linkSelector: 'a[href]',
      paranoia: "medium"
    },
    tiktok: {
      hosts: ["tiktok.com", "www.tiktok.com", "m.tiktok.com"],
      postSelector: '[data-e2e="recommend-list-item-container"], [data-e2e="comment-level-1"], [data-e2e="search-card-desc"], [class*="DivItemContainer"], [class*="CommentItem"]',
      feedSelector: '[data-e2e="recommend-list"], [data-e2e="comment-list"], main',
      linkSelector: 'a[href]',
      paranoia: "high"
    },
    soundcloud: {
      hosts: ["soundcloud.com", "www.soundcloud.com", "m.soundcloud.com"],
      postSelector: 'li[class*="soundList"], li[class*="track"], article, [role="listitem"]',
      feedSelector: 'main, body',
      linkSelector: 'a[href]',
      paranoia: "high",
      genericFallback: true,
      minTextLength: 10  // Catch short scam messages
    },
    youtube: {
      hosts: ["youtube.com", "www.youtube.com", "m.youtube.com"],
      postSelector: 'ytd-comment-renderer, ytd-post-renderer, ytd-backstage-post-renderer, #description-inline-expander, ytd-structured-description-content-renderer, .comment-renderer',
      feedSelector: '#comments, #contents, #below, #panels, main',
      linkSelector: 'a[href]',
      paranoia: "medium",
      genericFallback: true
    },
    linktree: {
      hosts: ["linktr.ee"],
      postSelector: 'a[data-testid="LinkButton"], [data-testid="StyledContainer"] a[href], main a[href]:not([href^="#"]):not([href^="/"]):not([href*="linktr.ee"])',
      feedSelector: 'main, [data-testid="ProfilePage"], #profile-container',
      linkSelector: 'a[href]',
      paranoia: "high",
      minTextLength: 5  // Link cards have short text
    }
  },

  // =========================================================
  // SCAM PATTERNS — checked against every post's text
  // =========================================================
  SCAM_PATTERNS: [
    // ---- Advance fee / 419 scams ----
    { pattern: /pay\s+(a\s+)?(small\s+)?(processing|transfer|handling|customs|clearance|release)\s+fee/i, category: "Advance Fee Scam", severity: "high" },
    { pattern: /fee\s+(is\s+)?(required|needed)\s+(before|to\s+(release|process|claim))/i, category: "Advance Fee Scam", severity: "high" },
    { pattern: /(beneficiary|next\s+of\s+kin|unclaimed\s+fund|deceased\s+client)/i, category: "Inheritance Scam", severity: "high" },
    { pattern: /bank\s+of\s+nigeria/i, category: "419 Scam", severity: "high" },
    { pattern: /confidential\s+(business|transaction)/i, category: "419 Scam", severity: "medium" },
    { pattern: /diplomatic\s+(bag|courier|channel)/i, category: "419 Scam", severity: "high" },

    // ---- Crypto scams ----
    { pattern: /enter\s+(your\s+)?(seed|recovery)\s+phrase/i, category: "Seed Phrase Theft", severity: "critical" },
    { pattern: /double\s+your\s+(crypto|bitcoin|eth|coin)/i, category: "Crypto Doubling Scam", severity: "critical" },
    { pattern: /send\s+(\w+\s+)?to\s+(this\s+)?(address|wallet)\s+(to\s+)?receive/i, category: "Crypto Scam", severity: "critical" },
    { pattern: /guaranteed\s+(returns?|profits?|daily|weekly|income)/i, category: "Investment Scam", severity: "high" },
    { pattern: /(\d{2,})%\s*(daily|weekly)\s*(return|profit|yield|gain)/i, category: "Unrealistic ROI", severity: "high" },
    { pattern: /connect\s+(your\s+)?wallet/i, category: "Wallet Connect Request", severity: "medium" },
    { pattern: /airdrop.*claim|claim.*airdrop/i, category: "Fake Airdrop", severity: "high" },
    { pattern: /free\s+(bitcoin|btc|eth|crypto|token|nft)/i, category: "Free Crypto Scam", severity: "medium" },
    { pattern: /mining\s+(contract|pool|reward)/i, category: "Mining Scam", severity: "medium" },
    { pattern: /private\s+key|seed\s+phrase|recovery\s+phrase/i, category: "Key Theft Risk", severity: "high" },

    // ---- Romance scams ----
    { pattern: /god\s+(led|brought|sent)\s+me\s+to\s+you/i, category: "Romance Scam", severity: "medium" },
    { pattern: /send\s+(me\s+)?money\s+(so\s+)?(i\s+)?can\s+(come|visit|travel)/i, category: "Romance Scam", severity: "high" },
    { pattern: /i('?m|\s+am)\s+stranded/i, category: "Romance Scam", severity: "medium" },
    { pattern: /deployed\s+overseas/i, category: "Military Romance Scam", severity: "medium" },
    { pattern: /i\s+trust\s+you\s+with\s+my\s+(life|everything)/i, category: "Romance Manipulation", severity: "medium" },
    { pattern: /you\s+are\s+the\s+only\s+(one|person)\s+i\s+(can\s+)?trust/i, category: "Romance Manipulation", severity: "medium" },

    // ---- Tech support ----
    { pattern: /your\s+(computer|device|system)\s+(is|has\s+been)\s+(infected|compromised|hacked)/i, category: "Fake Security Alert", severity: "high" },
    { pattern: /call\s+(now|immediately|this\s+number).*\d{3}/i, category: "Phone Scam", severity: "high" },
    { pattern: /error\s*(code\s*)?#?\s*0x[0-9a-f]{4,}/i, category: "Fake Error Code", severity: "high" },
    { pattern: /virus(es)?\s+(detected|found)/i, category: "Fake Virus Alert", severity: "high" },

    // ---- Authority impersonation / urgency ----
    { pattern: /your\s+account\s+(will\s+be|has\s+been)\s+(suspended|closed|terminated|locked|disabled)/i, category: "Account Threat", severity: "high" },
    { pattern: /verify\s+(your\s+)?(account|identity)\s+(within|before|immediately)/i, category: "Urgency Tactic", severity: "medium" },
    { pattern: /official\s+notice\s+from\s+(the\s+)?(irs|fbi|doj|ssa)/i, category: "Government Impersonation", severity: "high" },
    { pattern: /failure\s+to\s+(respond|comply|verify)\s+(will|may)\s+result/i, category: "Threat Language", severity: "medium" },

    // ---- Reward bait ----
    { pattern: /you('ve|\s+have)\s+(been\s+)?selected\s+(as\s+)?(a\s+)?(winner|lucky)/i, category: "Reward Scam", severity: "high" },
    { pattern: /claim\s+your\s+(prize|reward|winnings?|gift)\s*(now|today|here)?/i, category: "Prize Scam", severity: "high" },
    { pattern: /congratulations!?\s+you\s+(won|have\s+won|are\s+a\s+winner)/i, category: "Prize Scam", severity: "high" },
    { pattern: /spin\s+(the\s+)?wheel/i, category: "Fake Prize Wheel", severity: "medium" },

    // ---- Platform migration (move off-platform to avoid detection) ----
    { pattern: /(message|contact|add|text)\s+me\s+(on|at|via)\s+(whatsapp|telegram|signal|hangouts)/i, category: "Platform Migration", severity: "medium" },
    { pattern: /my\s+(whatsapp|telegram)\s+(number|is|:)/i, category: "Platform Migration", severity: "medium" },
    { pattern: /let'?s\s+(move|continue|chat)\s+(on|to|via)\s+(whatsapp|telegram|signal)/i, category: "Platform Migration", severity: "medium" },

    // ---- Money-making / MLM / Work-from-home scams ----
    { pattern: /i\s+(made|earned|got)\s+\$\s*[\d,]+\s*(in|from|per|this|last)\s*(a\s+)?(week|day|month|hour)/i, category: "Income Claim", severity: "medium" },
    { pattern: /earn\s+\$?\s*[\d,]+\s*(per|a|every|each)\s*(week|day|month|hour)/i, category: "Income Claim", severity: "medium" },
    { pattern: /work\s*(ing)?\s+from\s+home.*\$|(\$|earn).*work\s*(ing)?\s+from\s+home/i, category: "Work-From-Home Scam", severity: "medium" },
    { pattern: /be\s+your\s+own\s+boss/i, category: "MLM/Pyramid", severity: "low" },
    { pattern: /join\s+my\s+team/i, category: "MLM/Pyramid", severity: "low" },
    { pattern: /financial\s+freedom\s*(today|now|guaranteed|is\s+possible)?/i, category: "Income Scam", severity: "medium" },
    { pattern: /passive\s+income\s*(daily|weekly|monthly|guaranteed|opportunity)?/i, category: "Income Scam", severity: "medium" },
    { pattern: /life.?changing\s+(money|income|opportunity|amount)/i, category: "Income Scam", severity: "medium" },
    { pattern: /dm\s+(me|for)\s+(more\s+)?(info|details|opportunity)/i, category: "DM Solicitation", severity: "low" },
    { pattern: /link\s+in\s+(my\s+)?(bio|profile)/i, category: "Bio Link Solicitation", severity: "low" },
    { pattern: /limited\s+(spots?|slots?|openings?)\s+(left|available|remaining)/i, category: "Fake Scarcity", severity: "medium" },
    { pattern: /only\s+\d+\s+(spots?|slots?|left)/i, category: "Fake Scarcity", severity: "medium" },
    { pattern: /this\s+(won'?t|will\s+not)\s+last\s+(long|forever)/i, category: "Fake Scarcity", severity: "low" },

    // ---- Marketplace scams ----
    { pattern: /pay\s*(ment)?\s+(via|with|by|using)\s+(gift\s+card|itunes|google\s+play\s+card|steam\s+card)/i, category: "Gift Card Payment Scam", severity: "high" },
    { pattern: /pay\s*(ment)?\s+(via|with|by|using)\s+(zelle|venmo|cash\s*app|western\s+union|moneygram)\s+only/i, category: "Untraceable Payment", severity: "high" },
    { pattern: /wire\s+transfer\s+only/i, category: "Untraceable Payment", severity: "high" },
    { pattern: /no\s+(refund|return)s?\s*(accepted|available|possible|period)?/i, category: "No Refund Warning", severity: "low" },
    { pattern: /shipping\s+from\s+(overseas|china|abroad)/i, category: "Overseas Shipping", severity: "low" },

    // ---- Fake giveaways ----
    { pattern: /(like|share|follow|retweet|tag)\s+(and|&|to)\s+(win|enter|get|claim)/i, category: "Engagement Bait", severity: "low" },
    { pattern: /giveaway!?\s*(enter|click|follow|like|share|tag)/i, category: "Giveaway Bait", severity: "low" },
    { pattern: /(elon\s+musk|mr\s*beast|jeff\s+bezos)\s+(is\s+)?(giving\s+away|giveaway|crypto|bitcoin)/i, category: "Fake Celebrity Giveaway", severity: "high" },

    // ---- Loan scams ----
    { pattern: /pre-?approved\s+(for\s+a\s+)?(loan|credit|mortgage)/i, category: "Loan Scam", severity: "medium" },
    { pattern: /instant\s+(loan|credit|cash|approval)/i, category: "Loan Scam", severity: "medium" },
    { pattern: /no\s+credit\s+check\s+(required|needed|necessary)/i, category: "Loan Scam", severity: "medium" },
    { pattern: /bad\s+credit\s+(ok|accepted|welcome|no\s+problem)/i, category: "Loan Scam", severity: "medium" },

    // ---- Weight loss / health scams ----
    { pattern: /lost?\s+\d+\s*(lbs?|kg|pounds?)\s+(in|within)\s+\d+\s*(days?|weeks?)/i, category: "Weight Loss Scam", severity: "low" },
    { pattern: /doctors?\s+(hate|don'?t\s+want\s+you\s+to\s+know)/i, category: "Health Scam", severity: "medium" },
    { pattern: /miracle\s+(cure|pill|supplement|weight\s+loss)/i, category: "Health Scam", severity: "medium" },

    // ---- Impersonation / phishing ----
    { pattern: /i'?m\s+(a\s+)?representative\s+(of|from)\s+(facebook|meta|instagram|paypal|amazon|microsoft|x|twitter)/i, category: "Platform Impersonation", severity: "high" },
    { pattern: /customer\s+(service|support)\s+(here|representative|agent)/i, category: "Fake Support", severity: "medium" },
    { pattern: /your\s+(facebook|instagram|paypal|amazon|twitter|x)\s+(account|page)\s+(has\s+been|will\s+be|is)\s+(flagged|disabled|suspended|deleted|restricted)/i, category: "Fake Account Warning", severity: "high" },
    { pattern: /official\s+(page|account)\s+(of|for)/i, category: "Impersonation Risk", severity: "low" },
    { pattern: /verified\s+(by|account|badge|page)/i, category: "Fake Verification Claim", severity: "low" },
    { pattern: /this\s+is\s+(the\s+)?(real|official|authentic)\s+(me|account|page)/i, category: "Impersonation Risk", severity: "low" },

    // ---- X/Twitter-specific scams (crypto reply bots, impersonation, engagement farming) ----
    { pattern: /check\s+(my|the)\s+(pinned|first)\s+(tweet|post)/i, category: "Reply Bot", severity: "medium" },
    { pattern: /i'?ll\s+(teach|show|help)\s+you\s+(how\s+to\s+)?(make|earn|get)\s+\$?\d/i, category: "Guru Scam", severity: "medium" },
    { pattern: /reply\s+(with\s+)?["']?(interested|yes|info|me|ready)["']?\s*(below|here)?/i, category: "Engagement Farming", severity: "low" },
    { pattern: /drop\s+(a\s+)?["']?(yes|ready|info|me|interested)["']?\s+(below|if|and|to)/i, category: "Engagement Farming", severity: "low" },
    { pattern: /first\s+\d+\s+(people|followers|replies)\s+(to\s+)?(get|receive|win)/i, category: "Fake Giveaway", severity: "medium" },
    { pattern: /giving\s+away\s+\$?\d[\d,]*\s*(to|for|worth)/i, category: "Fake Cash Giveaway", severity: "medium" },
    { pattern: /invest\s*(ed|ing)?\s+\$?\d[\d,]*\s*(and|,)\s*(got|received|made|earned)\s+\$?\d[\d,]*/i, category: "Fake Testimonial", severity: "high" },
    { pattern: /thanks?\s+(to\s+)?(mr|mrs|dr|professor|master|coach|trader)\s+\w+\s*(for|who)/i, category: "Fake Testimonial", severity: "medium" },
    { pattern: /forex\s+(trader?|signal|mentor|coach|master|guru)/i, category: "Forex Scam", severity: "medium" },
    { pattern: /binary\s+(option|trading|signal)/i, category: "Binary Options Scam", severity: "high" },
    { pattern: /my\s+(trading\s+)?mentor\s+(helped|showed|taught)/i, category: "Fake Mentor Scam", severity: "medium" },
    { pattern: /pro[- ]?tip|insider\s+(info|tip|knowledge)/i, category: "Insider Tip Scam", severity: "low" },
    { pattern: /0x[a-fA-F0-9]{40}/i, category: "Crypto Wallet Address", severity: "medium" },

    // ---- Job / Employment scams ----
    { pattern: /hiring\s+(now|immediately|urgently)!?\s*(no\s+experience)?/i, category: "Job Scam", severity: "medium" },
    { pattern: /no\s+(experience|degree|resume)\s+(needed|required|necessary)/i, category: "Job Scam", severity: "medium" },
    { pattern: /earn\s+\$\d[\d,]*\s*(\/|\s+per\s+)(week|day|hour)\s*(from\s+home)?/i, category: "Job Scam", severity: "medium" },
    { pattern: /make\s+money\s+(online|from\s+home|from\s+your\s+phone)/i, category: "Job Scam", severity: "medium" },
    { pattern: /data\s+entry\s+(job|work|position).*\$\d/i, category: "Data Entry Scam", severity: "medium" },
    { pattern: /pay\s+(a\s+)?(registration|training|starter|kit)\s+fee/i, category: "Job Fee Scam", severity: "high" },
    { pattern: /secret\s+(shopper|mystery\s+shopper)/i, category: "Mystery Shopper Scam", severity: "medium" },
    { pattern: /envelope\s+stuffing/i, category: "Envelope Stuffing Scam", severity: "medium" },
    { pattern: /typing\s+(job|work|position)\s*(from\s+home)?/i, category: "Typing Scam", severity: "low" },
    { pattern: /we\s+found\s+your\s+(resume|profile|cv)/i, category: "Fake Recruiter", severity: "medium" },
    { pattern: /congratulations.*selected\s+for\s+(a\s+)?(position|job|role|interview)/i, category: "Fake Job Offer", severity: "high" },
    { pattern: /work\s+from\s+(home|anywhere).*\$\d[\d,]*\s*(per|a|daily|weekly)/i, category: "WFH Scam", severity: "medium" },

    // ---- Rental / Housing scams ----
    { pattern: /below\s+market\s+(price|value|rate|rent)/i, category: "Rental Scam", severity: "medium" },
    { pattern: /(deposit|rent)\s+(via|with|by)\s+(wire|zelle|venmo|cash\s*app|gift\s+card)/i, category: "Rental Payment Scam", severity: "high" },
    { pattern: /can'?t\s+(show|view|visit)\s+(the\s+)?(property|apartment|house|unit)\s+(in\s+person|right\s+now)/i, category: "Rental Scam", severity: "high" },
    { pattern: /i'?m\s+(out\s+of\s+(town|country|state)|overseas|abroad|deployed|traveling)\s*(right\s+now|currently)?.*\s+(key|property|rent|lease)/i, category: "Rental Scam", severity: "high" },
    { pattern: /send\s+(the\s+)?deposit\s+(first|now|today|before)/i, category: "Rental Deposit Scam", severity: "high" },
    { pattern: /first\s+month.?s?\s+rent\s+(plus|and|\+)\s+deposit\s+(via|through|by)/i, category: "Rental Payment Scam", severity: "medium" },
    { pattern: /available\s+immediately.*no\s+(lease|credit\s+check)/i, category: "Rental Scam", severity: "medium" },

    // ---- Ticket / Event scams ----
    { pattern: /selling\s+(my\s+)?(tickets?|passes?)\s+(for|to|at)\s+(a\s+)?(discount|less|half|cheap)/i, category: "Ticket Scam", severity: "medium" },
    { pattern: /(sold\s+out|last\s+minute)\s+(tickets?|passes?)\s+available/i, category: "Ticket Scam", severity: "medium" },
    { pattern: /can'?t\s+(go|make\s+it|attend).*selling\s+(my\s+)?tickets?/i, category: "Ticket Scam Risk", severity: "low" },
    { pattern: /vip\s+(tickets?|passes?|access)\s+(for\s+sale|available|at\s+a\s+discount)/i, category: "VIP Ticket Scam", severity: "medium" },
    { pattern: /meet\s+and\s+greet\s+(passes?|tickets?|packages?)\s+available/i, category: "Fake Meet & Greet", severity: "medium" },

    // ---- Pet scams ----
    { pattern: /free\s+(puppy|puppies|kitten|kittens|dog|cat)\s+(to\s+)?(a\s+)?(good\s+)?home/i, category: "Pet Scam Risk", severity: "low" },
    { pattern: /(puppy|kitten|dog|cat)\s+(for\s+)?(adoption|sale).*\$\d/i, category: "Pet Scam Risk", severity: "low" },
    { pattern: /shipping\s+(fee|cost)\s+(for|to\s+deliver)\s+(the\s+)?(puppy|kitten|pet|dog|cat)/i, category: "Pet Shipping Scam", severity: "high" },
    { pattern: /pet\s+(transportation|delivery|shipping)\s+(insurance|fee|cost|charge)/i, category: "Pet Shipping Scam", severity: "high" },
    { pattern: /akc\s+registered.*\$\d/i, category: "Fake Breeder", severity: "medium" },

    // ---- Charity / Disaster scams ----
    { pattern: /donate\s+(now|today|here|directly)\s*(to\s+)?(help|save|support)?/i, category: "Donation Solicitation", severity: "low" },
    { pattern: /100%\s+(of\s+)?(all\s+)?(donations?|proceeds)\s+(go|goes)\s+(directly\s+)?to/i, category: "Charity Scam Risk", severity: "medium" },
    { pattern: /send\s+(donations?|money|funds?)\s+(to|via)\s+(this\s+)?(cash\s*app|venmo|zelle|paypal|bitcoin|btc)/i, category: "Suspicious Donation", severity: "high" },
    { pattern: /go\s*fund\s*me.*share|share.*go\s*fund\s*me/i, category: "GoFundMe Share Request", severity: "low" },
    { pattern: /my\s+(child|baby|son|daughter|family|mother|father)\s+(is\s+)?(sick|dying|has\s+cancer|needs?\s+surgery)/i, category: "Sympathy Scam Risk", severity: "medium" },

    // ---- Tax / Government scams ----
    { pattern: /irs\s+(refund|payment|stimulus|deposit)/i, category: "IRS Scam", severity: "high" },
    { pattern: /tax\s+(refund|rebate)\s+(available|ready|pending)/i, category: "Tax Scam", severity: "high" },
    { pattern: /government\s+(grant|payment|stimulus|relief)\s+(available|free|for\s+you)/i, category: "Government Grant Scam", severity: "high" },
    { pattern: /you\s+(qualify|are\s+eligible)\s+for\s+(a\s+)?(free\s+)?(government|federal|state)\s+(grant|money|fund)/i, category: "Government Grant Scam", severity: "high" },
    { pattern: /social\s+security\s+(number|benefit|payment)\s+(has\s+been|is)\s+(suspended|compromised|frozen)/i, category: "SSA Scam", severity: "high" },
    { pattern: /unclaimed\s+(tax|government|federal)\s+(refund|money|payment|fund)/i, category: "Unclaimed Money Scam", severity: "high" },

    // ---- Shipping / Delivery scams ----
    { pattern: /your\s+(package|parcel|order|delivery)\s+(is|has\s+been)\s+(held|delayed|stuck|pending|waiting)/i, category: "Delivery Scam", severity: "medium" },
    { pattern: /pay\s+(a\s+)?(customs?|delivery|shipping|clearance)\s+(fee|charge|duty)\s+(to\s+)?(release|receive|claim)/i, category: "Delivery Fee Scam", severity: "high" },
    { pattern: /schedule\s+your\s+delivery|redelivery\s+fee/i, category: "Delivery Scam", severity: "medium" },
    { pattern: /(usps|fedex|ups|dhl)\s+(package|parcel|order)\s+(notification|alert|update)/i, category: "Fake Delivery Alert", severity: "medium" },

    // ---- Subscription / Free trial traps ----
    { pattern: /free\s+trial.*credit\s+card|credit\s+card.*free\s+trial/i, category: "Subscription Trap", severity: "medium" },
    { pattern: /only\s+(pay|covers?)\s+(for\s+)?(shipping|postage|handling)/i, category: "Hidden Subscription", severity: "medium" },
    { pattern: /cancel\s+anytime.*act\s+now|act\s+now.*cancel\s+anytime/i, category: "Subscription Pressure", severity: "low" },
    { pattern: /exclusive\s+(membership|access|club)\s*(only|just)\s+\$\d/i, category: "Membership Trap", severity: "medium" },

    // ---- QR code scams ----
    { pattern: /scan\s+(this|the|my)\s+qr\s+code/i, category: "QR Code Risk", severity: "medium" },
    { pattern: /qr\s+code\s+(to|for)\s+(claim|get|receive|win|access|pay)/i, category: "QR Code Scam", severity: "medium" },

    // ---- Cash flipping / Money multiplication ----
    { pattern: /cash\s+flip(ping)?/i, category: "Cash Flipping Scam", severity: "high" },
    { pattern: /turn\s+\$?\d[\d,]*\s+(into|to)\s+\$?\d[\d,]*/i, category: "Money Multiplication Scam", severity: "high" },
    { pattern: /send\s+\$?\d[\d,]*\s*(and|,)?\s*(get|receive|i'?ll\s+send)\s*(back\s+)?\$?\d[\d,]*/i, category: "Cash Flipping Scam", severity: "high" },
    { pattern: /money\s+(flip|double|multiply|method)/i, category: "Cash Flipping Scam", severity: "high" },
    { pattern: /who\s+(wants?|needs?)\s+(a\s+)?(cash\s+)?flip/i, category: "Cash Flipping Scam", severity: "high" },
    { pattern: /bless(ing)?\s+(someone|people|you)\s+with\s+(cash|money|\$)/i, category: "Cash Blessing Scam", severity: "medium" },

    // ---- Sugar daddy / Sugar mommy scams ----
    { pattern: /sugar\s+(daddy|mommy|mama|baby)/i, category: "Sugar Scam", severity: "medium" },
    { pattern: /looking\s+for\s+(a\s+)?loyal\s+(sugar\s+)?(baby|babe)/i, category: "Sugar Scam", severity: "medium" },
    { pattern: /i'?ll\s+(pay|send|give)\s+(you\s+)?\$?\d[\d,]*\s*(weekly|daily|per\s+week|allowance)/i, category: "Sugar Scam", severity: "high" },
    { pattern: /weekly\s+allowance\s+of\s+\$?\d[\d,]*/i, category: "Sugar Scam", severity: "high" },
    { pattern: /need\s+(a\s+)?(loyal|honest|trustworthy)\s+(sugar\s+)?(baby|babe)/i, category: "Sugar Scam", severity: "medium" },

    // ---- Sextortion / Blackmail ----
    { pattern: /i\s+(have|got)\s+(your\s+)?(private|intimate|explicit)\s+(photos?|pictures?|videos?|content)/i, category: "Sextortion Threat", severity: "critical" },
    { pattern: /(pay|send)\s+(or|otherwise)\s+(i'?ll|we\s+will)\s+(release|share|post|send|publish)/i, category: "Blackmail Threat", severity: "critical" },
    { pattern: /i'?ll\s+(expose|leak|share|release|publish)\s+(your\s+)?(photos?|pictures?|videos?|secrets?)/i, category: "Blackmail Threat", severity: "critical" },
    { pattern: /i\s+recorded\s+(you|your\s+screen|your\s+webcam)/i, category: "Sextortion Scam", severity: "critical" },
    { pattern: /your\s+(camera|webcam)\s+(was|has\s+been)\s+(hacked|compromised|accessed)/i, category: "Sextortion Scam", severity: "critical" },

    // ---- Refund / Overpayment scams ----
    { pattern: /accidentally\s+(sent|paid|transferred)\s+(you\s+)?(too\s+much|\$?\d)/i, category: "Overpayment Scam", severity: "high" },
    { pattern: /please\s+(send|refund|return)\s+(the\s+)?(difference|extra|overpayment)/i, category: "Overpayment Scam", severity: "high" },
    { pattern: /you\s+(are|have\s+been)\s+(owed|due)\s+(a\s+)?refund/i, category: "Fake Refund", severity: "medium" },
    { pattern: /claim\s+your\s+refund/i, category: "Fake Refund", severity: "medium" },
    { pattern: /pending\s+refund.*verify|verify.*pending\s+refund/i, category: "Fake Refund", severity: "high" },

    // ---- Pyramid / Ponzi explicit language ----
    { pattern: /recruit\s+(\d+\s+)?(members?|people|friends?|partners?)\s+(and|to)\s+(earn|get|receive)/i, category: "Pyramid Scheme", severity: "high" },
    { pattern: /down\s*line|up\s*line/i, category: "MLM Language", severity: "medium" },
    { pattern: /matrix\s+(program|system|plan|opportunity)/i, category: "Matrix Scheme", severity: "high" },
    { pattern: /gifting\s+(circle|table|program)/i, category: "Gifting Circle Scam", severity: "high" },
    { pattern: /blessing\s+(loom|circle)/i, category: "Blessing Loom Scam", severity: "high" },
    { pattern: /get\s+paid\s+(to|for)\s+recruit(ing)?/i, category: "Pyramid Scheme", severity: "high" },

    // ---- Fake scholarship / Education scams ----
    { pattern: /guaranteed\s+scholarship/i, category: "Scholarship Scam", severity: "high" },
    { pattern: /scholarship\s+(fee|application\s+fee|processing\s+fee)/i, category: "Scholarship Fee Scam", severity: "high" },
    { pattern: /you('ve|\s+have)\s+been\s+(awarded|selected\s+for)\s+(a\s+)?scholarship/i, category: "Fake Scholarship", severity: "high" },
    { pattern: /free\s+money\s+for\s+(college|school|education|university)/i, category: "Scholarship Scam Risk", severity: "medium" },

    // ---- Immigration scams ----
    { pattern: /guaranteed\s+(visa|green\s+card|citizenship|work\s+permit)/i, category: "Immigration Scam", severity: "high" },
    { pattern: /lottery\s+(visa|green\s+card)\s+(winner|result|selected)/i, category: "Visa Lottery Scam", severity: "high" },
    { pattern: /immigration\s+(lawyer|attorney|agent)\s*(fee|charges?|special\s+rate)/i, category: "Immigration Scam Risk", severity: "medium" },

    // ---- Insurance / Warranty scams ----
    { pattern: /your\s+(car|vehicle|auto)\s+(warranty|insurance)\s+(has\s+expired|is\s+expiring|about\s+to\s+expire)/i, category: "Warranty Scam", severity: "high" },
    { pattern: /extended\s+(warranty|protection)\s+(offer|deal|available)/i, category: "Extended Warranty Scam", severity: "medium" },
    { pattern: /final\s+(notice|warning).*warranty/i, category: "Warranty Scam", severity: "high" },

    // ---- Timeshare / Vacation scams ----
    { pattern: /free\s+(vacation|trip|cruise|holiday)\s*(to|for|if|when)/i, category: "Vacation Scam", severity: "medium" },
    { pattern: /timeshare\s+(presentation|offer|opportunity)/i, category: "Timeshare Pitch", severity: "low" },
    { pattern: /you('ve|\s+have)\s+(won|been\s+selected\s+for)\s+(a\s+)?(free\s+)?(vacation|trip|cruise)/i, category: "Vacation Scam", severity: "high" },
    { pattern: /all[\s-]inclusive\s+(resort|vacation|trip)\s*(only|just|for)\s+\$\d/i, category: "Vacation Scam Risk", severity: "medium" },

    // ---- Fake news / Clickbait ----
    { pattern: /you\s+won'?t\s+believe\s+what\s+happened/i, category: "Clickbait", severity: "low" },
    { pattern: /shocking\s+(truth|news|reveal|video|photos?)/i, category: "Clickbait", severity: "low" },
    { pattern: /this\s+(video|photo|story)\s+is\s+going\s+viral/i, category: "Clickbait", severity: "low" },
    { pattern: /the\s+(government|media|they)\s+(doesn'?t|don'?t)\s+want\s+you\s+to\s+(know|see)/i, category: "Conspiracy Clickbait", severity: "low" },
    { pattern: /leaked\s+(video|photos?|documents?|footage)/i, category: "Clickbait", severity: "low" },
    { pattern: /celebrity.*died|died.*celebrity/i, category: "Death Hoax Clickbait", severity: "low" },

    // ---- Facebook Marketplace specific ----
    { pattern: /still\s+available\??.*cash\s+only/i, category: "Marketplace Caution", severity: "low", platforms: ["facebook"] },
    { pattern: /my\s+(husband|wife|son|daughter|relative)\s+(left|passed|doesn'?t\s+need)/i, category: "Emotional Marketplace Pitch", severity: "low", platforms: ["facebook"] },
    { pattern: /moving\s+(sale|away|overseas).*must\s+(sell|go)/i, category: "Urgency Marketplace Pitch", severity: "low", platforms: ["facebook"] },
    { pattern: /(pick\s+up|meet)\s+at\s+(a\s+)?(gas\s+station|parking\s+lot|neutral\s+location)/i, category: "Marketplace Safety", severity: "low", platforms: ["facebook"] },
    { pattern: /i'?ll\s+(ship|send|mail)\s+(it|the\s+item).*pay\s+(first|upfront|in\s+advance)/i, category: "Marketplace Prepayment Scam", severity: "high", platforms: ["facebook"] },
    { pattern: /deposit\s+(to\s+)?hold\s+(it|the\s+item)/i, category: "Marketplace Deposit Scam", severity: "medium", platforms: ["facebook"] },
    { pattern: /send\s+(a\s+)?verification\s+code/i, category: "Verification Code Scam", severity: "high" },
    { pattern: /google\s+voice\s+(verification|code|number)/i, category: "Google Voice Scam", severity: "high" },

    // ---- Instagram specific ----
    { pattern: /brand\s+(ambassador|collab(oration)?|partnership|deal)/i, category: "Fake Brand Deal", severity: "low", platforms: ["instagram"] },
    { pattern: /we'?d\s+love\s+(to|for\s+you\s+to)\s+(feature|promote|collaborate|partner)/i, category: "Fake Collab Request", severity: "low", platforms: ["instagram"] },
    { pattern: /send\s+us\s+(a\s+)?dm\s+(for|to\s+get)\s+(a\s+)?discount/i, category: "DM Discount Scam", severity: "low", platforms: ["instagram"] },
    { pattern: /get\s+\d+k?\+?\s+(followers|likes|views)\s+(in|within|under)/i, category: "Fake Follower Service", severity: "medium", platforms: ["instagram", "x", "tiktok"] },
    { pattern: /buy\s+(real\s+)?(followers|likes|views|engagement)/i, category: "Fake Engagement Service", severity: "medium", platforms: ["instagram", "x", "tiktok"] },
    { pattern: /grow\s+your\s+(account|following|page)\s+(fast|instantly|overnight)/i, category: "Fake Growth Service", severity: "medium", platforms: ["instagram", "x", "tiktok"] },

    // ---- YouTube specific ----
    { pattern: /sub(scribe)?\s+(to\s+)?my\s+channel/i, category: "Sub4Sub Spam", severity: "low", platforms: ["youtube"] },
    { pattern: /sub\s*4\s*sub|follow\s*4\s*follow|f4f|s4s/i, category: "Sub4Sub Spam", severity: "low", platforms: ["youtube", "instagram", "tiktok"] },
    { pattern: /check\s+out\s+my\s+(channel|video|content)/i, category: "Self-Promo Spam", severity: "low", platforms: ["youtube"] },
    { pattern: /free\s+(v[\-]?bucks|robux|coins?|gems?|diamonds?)/i, category: "Game Currency Scam", severity: "high" },
    { pattern: /(v[\-]?bucks|robux)\s+(generator|hack|free|glitch|method)/i, category: "Game Currency Scam", severity: "high" },

    // ---- Fake verification / Blue check scams ----
    { pattern: /get\s+(verified|your\s+blue\s+(check|tick|badge))/i, category: "Fake Verification", severity: "medium" },
    { pattern: /verified\s+(badge|check|tick)\s+(for\s+)?(only|just)\s+\$?\d/i, category: "Fake Verification Sale", severity: "high" },
    { pattern: /apply\s+for\s+verification\s+(here|now|today)/i, category: "Fake Verification", severity: "medium" },

    // ---- Fake invoice / Payment request ----
    { pattern: /invoice\s+#?\d+.*\$([\d,]+\.?\d*)/i, category: "Fake Invoice", severity: "high" },
    { pattern: /payment\s+(due|overdue|outstanding|pending)\s*(of\s+)?\$/i, category: "Fake Invoice", severity: "high" },
    { pattern: /your\s+(subscription|membership|order)\s+(has\s+been|was)\s+(renewed|charged|billed)/i, category: "Fake Billing Alert", severity: "high" },
    { pattern: /unauthorized\s+(charge|transaction|payment|purchase)\s+(of|for)\s+\$/i, category: "Fake Charge Alert", severity: "high" },

    // ---- Password / Credential harvesting ----
    { pattern: /reset\s+your\s+password\s+(immediately|now|here)/i, category: "Credential Harvesting", severity: "high" },
    { pattern: /your\s+password\s+(has\s+been|was)\s+(compromised|leaked|exposed|found)/i, category: "Fake Password Alert", severity: "high" },
    { pattern: /unusual\s+(sign[\s-]?in|login|activity)\s+(attempt|detected|from)/i, category: "Fake Login Alert", severity: "medium" },
    { pattern: /someone\s+(tried\s+to|is\s+trying\s+to)\s+(access|log\s*in\s*to|hack)\s+your\s+account/i, category: "Fake Security Alert", severity: "high" },

    // ---- Survey scams ----
    { pattern: /complete\s+(this|a)\s+(short\s+)?(survey|questionnaire)\s+(to|and)\s+(win|get|receive|claim)/i, category: "Survey Scam", severity: "medium" },
    { pattern: /take\s+(this|our|a)\s+survey.*\$?\d+\s*(gift\s+card|cash|reward)/i, category: "Survey Scam", severity: "medium" },
    { pattern: /your\s+opinion\s+(is\s+)?worth\s+\$?\d/i, category: "Survey Scam", severity: "medium" },

    // ---- Fake app / Software scams ----
    { pattern: /download\s+(this|my|our|the)\s+(free\s+)?(app|software|tool|program)\s+(to|and)\s+(earn|make|win|get)/i, category: "Fake App Scam", severity: "high" },
    { pattern: /this\s+(app|bot|software|tool)\s+(makes?|earns?|generates?)\s+\$?\d[\d,]*\s*(per|a|daily|weekly)/i, category: "Fake Earning App", severity: "high" },
    { pattern: /get\s+paid\s+(to|for)\s+(watch(ing)?|click(ing)?|lik(e|ing)|view(ing)?)/i, category: "Fake Earning App", severity: "medium" },

    // ---- Debt / Financial relief scams ----
    { pattern: /eliminate\s+(your\s+)?(debt|student\s+loans?|credit\s+card\s+debt)/i, category: "Debt Relief Scam", severity: "medium" },
    { pattern: /debt\s+(forgiveness|relief|consolidation)\s+(program|plan|offer)\s*(free|available|now)?/i, category: "Debt Relief Scam", severity: "medium" },
    { pattern: /student\s+loan\s+(forgiveness|cancellation|relief)\s+(apply|available|free)/i, category: "Student Loan Scam", severity: "medium" },
    { pattern: /settle\s+your\s+debt\s+for\s+(pennies|cents|less)/i, category: "Debt Settlement Scam", severity: "medium" },

    // ---- Fake emergency / Distress scams ----
    { pattern: /i'?m\s+(stuck|stranded|trapped)\s+(in|at|overseas|abroad)/i, category: "Distress Scam", severity: "medium" },
    { pattern: /i\s+(was|got)\s+(robbed|mugged|kidnapped|arrested)/i, category: "Distress Scam", severity: "medium" },
    { pattern: /please\s+(wire|send|transfer)\s+money\s+(urgently|immediately|asap|now)/i, category: "Emergency Money Request", severity: "high" },
    { pattern: /i'?ll\s+pay\s+(you\s+)?back\s+(as\s+soon\s+as|when\s+i|tomorrow|next\s+week)/i, category: "Money Request", severity: "low" },
    { pattern: /hospital\s+(bill|fees?).*help|help.*hospital\s+(bill|fees?)/i, category: "Medical Emergency Scam", severity: "medium" },

    // ---- AI / Deepfake indicators ----
    { pattern: /ai[\s-]?(generated|powered|trading|bot|earns?|makes?)/i, category: "AI Scam Tool", severity: "medium" },
    { pattern: /(trading|earning|money)\s+(bot|robot|ai|algorithm)\s+(that|which|guaranteed)/i, category: "AI Trading Scam", severity: "high" },
    { pattern: /chat\s*gpt\s+(money|earn|hack|method|trading|passive\s+income)/i, category: "AI Income Scam", severity: "medium" },
    { pattern: /ai\s+clone|clone\s+my\s+voice|deepfake/i, category: "Deepfake Risk", severity: "medium" },

    // ---- Gift card scams (expanded) ----
    { pattern: /buy\s+(a\s+)?(gift\s+card|itunes\s+card|google\s+play\s+card|steam\s+card)\s+(and|then)\s+send/i, category: "Gift Card Scam", severity: "high" },
    { pattern: /send\s+(the\s+)?(gift\s+card\s+)?(code|number|pin|redemption)/i, category: "Gift Card Scam", severity: "high" },
    { pattern: /pay\s+(in|with|using|via)\s+gift\s+cards?/i, category: "Gift Card Payment", severity: "high" },

    // ---- Account takeover / SIM swap ----
    { pattern: /i\s+(lost|can'?t\s+access)\s+my\s+account.*help/i, category: "Account Recovery Scam", severity: "low" },
    { pattern: /verification\s+code\s+(was|just)\s+sent\s+to\s+(your|my)/i, category: "Verification Code Scam", severity: "high" },
    { pattern: /can\s+you\s+forward\s+(the|a|my)\s+(code|otp|verification)/i, category: "OTP Theft", severity: "critical" },

    // ---- Counterfeit / Replica goods ----
    { pattern: /(replica|1:1|aaa\s*\+*|mirror\s+quality)\s+(watch|bag|shoes?|sneakers?|designer)/i, category: "Counterfeit Goods", severity: "medium" },
    { pattern: /(gucci|louis\s*vuitton|rolex|nike|jordan)\s*(for\s+)?(only|just)\s+\$\d{1,2}/i, category: "Counterfeit Goods", severity: "high" },
    { pattern: /factory\s+direct\s+(price|deal|wholesale)/i, category: "Counterfeit Risk", severity: "low" },

    // ---- Lottery / Sweepstakes ----
    { pattern: /your\s+(email|number|phone)\s+(was|has\s+been)\s+(randomly\s+)?selected/i, category: "Lottery Scam", severity: "high" },
    { pattern: /you('ve|\s+have)\s+won\s+(a\s+)?\$?[\d,]+\s*(in\s+)?(the\s+)?(lottery|sweepstakes|draw)/i, category: "Lottery Scam", severity: "high" },
    { pattern: /international\s+(lottery|sweepstakes)\s+(winner|notification|result)/i, category: "International Lottery Scam", severity: "high" },
    { pattern: /winning\s+(ticket|number|notification)\s+(ref|reference|id)/i, category: "Lottery Scam", severity: "high" },
    { pattern: /prize\s+claim\s+(agent|office|department)/i, category: "Lottery Scam", severity: "high" },

    // ---- Hacking services ----
    { pattern: /hire\s+(a\s+)?(hacker|ethical\s+hacker)/i, category: "Hacking Service Scam", severity: "high" },
    { pattern: /hack\s+(any\s+)?(account|instagram|facebook|snapchat|whatsapp|email|phone)/i, category: "Hacking Service Scam", severity: "high" },
    { pattern: /recover\s+(hacked|stolen|lost)\s+(account|instagram|facebook)/i, category: "Account Recovery Scam", severity: "medium" },
    { pattern: /spy\s+(on|app|software|tool)\s*(your|someone|partner|spouse|cheating)/i, category: "Spyware Scam", severity: "high" },

    // ---- Fake legal threats ----
    { pattern: /legal\s+(action|proceedings?)\s+(will\s+be|has\s+been)\s+(taken|initiated|filed)/i, category: "Legal Threat Scam", severity: "high" },
    { pattern: /you\s+(are|have\s+been)\s+(being\s+)?(sued|charged|indicted)/i, category: "Legal Threat Scam", severity: "high" },
    { pattern: /arrest\s+warrant\s+(has\s+been|was)\s+(issued|filed)/i, category: "Fake Arrest Warrant", severity: "high" },
    { pattern: /court\s+(summons|hearing|appearance)\s+(scheduled|required|mandatory)/i, category: "Fake Court Notice", severity: "high" },

    // ---- Pig butchering (sha zhu pan) — the #1 global crypto scam ----
    { pattern: /sorry\s+(wrong\s+(number|person)|i\s+didn'?t\s+mean\s+to)/i, category: "Wrong Number Opener", severity: "low" },
    { pattern: /oh\s+(you\s+seem\s+)?(nice|interesting|friendly|kind).*where\s+(are|do)\s+you/i, category: "Pig Butchering Opener", severity: "medium" },
    { pattern: /i\s+(accidentally|mistakenly)\s+(added|messaged|texted|contacted)\s+(you|the\s+wrong)/i, category: "Wrong Number Scam", severity: "medium" },
    { pattern: /my\s+(uncle|aunt|friend|cousin)\s+(works?|is)\s+(in|at)\s+(finance|crypto|trading|investment)/i, category: "Pig Butchering", severity: "high" },
    { pattern: /i\s+know\s+(a\s+)?(great|good|amazing|reliable)\s+(investment|trading)\s+(platform|app|opportunity)/i, category: "Pig Butchering", severity: "high" },
    { pattern: /do\s+you\s+(invest|trade|know\s+about)\s*(crypto|bitcoin|forex|stock)/i, category: "Pig Butchering Probe", severity: "medium" },
    { pattern: /let\s+me\s+(show|teach|help)\s+you\s+(how\s+to\s+)?(invest|trade|make\s+money)/i, category: "Pig Butchering", severity: "high" },
    { pattern: /this\s+(platform|app|site)\s+(is\s+)?(regulated|licensed|safe|secure)\s+(by|and)/i, category: "Fake Platform Legitimacy", severity: "medium" },
    { pattern: /i('ve|\s+have)\s+(already|just)\s+(made|earned|withdrawn)\s+\$?\d[\d,]*\s*(from|on|with)\s+(this|the)\s+(platform|app)/i, category: "Pig Butchering Testimonial", severity: "high" },
    { pattern: /you\s+(just|only)\s+need\s+(to\s+)?(deposit|invest|put\s+in)\s+\$?\d/i, category: "Pig Butchering Deposit", severity: "high" },
    { pattern: /minimum\s+(deposit|investment)\s+(is\s+)?(only|just)\s+\$?\d/i, category: "Pig Butchering Deposit", severity: "medium" },

    // ---- Brushing scams ----
    { pattern: /received?\s+(a\s+)?(package|parcel|item)\s+(you\s+)?didn'?t\s+order/i, category: "Brushing Scam", severity: "medium" },
    { pattern: /scan\s+(the|this)\s+(qr|barcode)\s+(code\s+)?(on|inside)\s+(the\s+)?(package|parcel|box)/i, category: "Brushing QR Scam", severity: "high" },
    { pattern: /mystery\s+(package|box|parcel)\s+(arrived|showed\s+up|delivered)/i, category: "Brushing Scam", severity: "medium" },

    // ---- Task / Click-farm scams (Telegram, WhatsApp, FB) ----
    { pattern: /get\s+paid\s+(to\s+)?(complete|do|finish)\s+(simple\s+)?tasks?/i, category: "Task Scam", severity: "high" },
    { pattern: /complete\s+(simple\s+)?tasks?\s+(and|to)\s+(earn|get|receive)\s+\$?\d/i, category: "Task Scam", severity: "high" },
    { pattern: /task\s+(commission|bonus|reward)\s+\$?\d/i, category: "Task Scam", severity: "high" },
    { pattern: /deposit\s+(to\s+)?(unlock|access)\s+(higher|more|premium)\s+(tasks?|levels?|earnings?)/i, category: "Task Scam Deposit Trap", severity: "critical" },
    { pattern: /like\s+(and\s+)?(review|rate)\s+(products?|apps?|videos?)\s+(and\s+)?(earn|get\s+paid)/i, category: "Task Scam", severity: "high" },
    { pattern: /daily\s+(tasks?|missions?)\s+(earn|pay|reward)/i, category: "Task Scam", severity: "medium" },
    { pattern: /commission\s+(per|for\s+each|every)\s+(task|order|review)/i, category: "Task Scam", severity: "high" },

    // ---- Zelle-specific scam flows ----
    { pattern: /upgrade\s+(to|your)\s+(zelle\s+)?(business|premium)\s+account/i, category: "Zelle Scam", severity: "high" },
    { pattern: /zelle\s+(limit|daily\s+limit|transaction\s+limit)\s+(exceeded|reached|hit)/i, category: "Zelle Scam", severity: "high" },
    { pattern: /zelle\s+(payment|transfer)\s+(pending|failed|on\s+hold).*upgrade/i, category: "Zelle Scam", severity: "high" },

    // ---- Fake recovery services (targets scam victims) ----
    { pattern: /recover\s+(your\s+)?(lost|stolen|scammed)\s+(money|funds?|crypto|bitcoin)/i, category: "Recovery Scam", severity: "high" },
    { pattern: /i\s+(was\s+)?(also\s+)?scammed\s+(but|and)\s+(this|someone|a)\s+(person|hacker|expert)/i, category: "Recovery Scam", severity: "high" },
    { pattern: /ethical\s+hacker\s+(helped|recovered|got\s+back)\s+my\s+(money|funds?|crypto)/i, category: "Recovery Scam", severity: "high" },
    { pattern: /contact\s+.{1,30}\s+(to\s+)?(recover|retrieve|get\s+back)\s+(your\s+)?(money|funds?|crypto)/i, category: "Recovery Scam", severity: "high" },

    // ---- SoundCloud / Music platform scams ----
    { pattern: /buy\s+(real\s+)?(plays?|streams?|listeners?|followers?|reposts?|likes?)\s*(for\s+)?(cheap|only|just|\$)/i, category: "Fake Engagement Service", severity: "medium", platforms: ["soundcloud", "youtube"] },
    { pattern: /(get|buy|boost)\s+\d+k?\+?\s*(plays?|streams?|followers?|reposts?|listeners?)/i, category: "Fake Engagement Service", severity: "medium", platforms: ["soundcloud", "youtube"] },
    { pattern: /promo(te|tion)?\s+(your\s+)?(track|song|music|beat|album)\s*(to|for)\s*\d+k?\+?\s*(listeners?|followers?|people)/i, category: "Fake Promotion Service", severity: "medium", platforms: ["soundcloud", "youtube"] },
    { pattern: /send\s+(your\s+)?(track|beat|music|song)\s+(to|for)\s+(a\s+)?(free\s+)?(review|promo|feature|repost)/i, category: "Promo Scam Risk", severity: "low", platforms: ["soundcloud", "youtube"] },
    { pattern: /(a&r|label|record\s+label|major\s+label)\s+(is\s+)?(looking|searching|scouting)\s+(for|at)\s+(new\s+)?(talent|artists?|music)/i, category: "Fake Label Scout", severity: "medium", platforms: ["soundcloud", "youtube"] },
    { pattern: /sign(ed|ing)?\s+(artists?|talent)\s+(to|for)\s+(our|a|the)\s+(label|deal|contract)/i, category: "Fake Record Deal", severity: "medium", platforms: ["soundcloud", "youtube"] },
    { pattern: /i('m|\s+am)\s+(a\s+)?(producer|a&r|scout|manager)\s+(at|for|from|with)\s+/i, category: "Fake Industry Contact", severity: "low", platforms: ["soundcloud", "youtube"] },
    { pattern: /pay\s+(for\s+)?(a\s+)?(feature|verse|collab(oration)?)\s+(with|from|by)/i, category: "Paid Feature Scam Risk", severity: "low", platforms: ["soundcloud", "youtube"] },
    { pattern: /free\s+(beats?|instrumentals?|type\s+beats?)\s*(link|download|dm)/i, category: "Free Beat Bait", severity: "low", platforms: ["soundcloud", "youtube"] },
    { pattern: /guarantee\s+(you\s+)?(plays?|streams?|viral|views?|listeners?)/i, category: "Fake Guarantee", severity: "high", platforms: ["soundcloud", "youtube"] },
    { pattern: /get\s+(signed|noticed|discovered)\s+(by\s+)?(a\s+)?(major\s+)?(label|record|industry)/i, category: "Fake Discovery Promise", severity: "medium", platforms: ["soundcloud", "youtube"] },
    { pattern: /submit\s+(your\s+)?(music|track|song|beat)\s+(here|now|today)\s*(for\s+)?(consideration|review|feature|playlist)/i, category: "Music Submission Scam", severity: "low", platforms: ["soundcloud", "youtube"] },
    { pattern: /playlist\s+(placement|submission|feature)\s*(only|just)?\s*\$?\d/i, category: "Paid Playlist Scam", severity: "medium", platforms: ["soundcloud", "youtube"] },

    // ---- Fake urgency / FOMO amplifiers ----
    { pattern: /last\s+(chance|day|hour|opportunity)\s+(to\s+)?(join|buy|invest|claim|get)/i, category: "FOMO Manipulation", severity: "medium" },
    { pattern: /offer\s+(expires?|ends?)\s+(in\s+)?\d+\s*(hours?|minutes?|mins?)/i, category: "Fake Time Pressure", severity: "medium" },
    { pattern: /only\s+(available|open)\s+(for|to)\s+(the\s+)?(first|next)\s+\d+/i, category: "Fake Scarcity", severity: "medium" },
    { pattern: /act\s+(fast|now|quickly|immediately)\s+(before|or)/i, category: "Urgency Manipulation", severity: "low" },

    // ---- Weaponized generosity (builds trust to scam later) ----
    { pattern: /i'?m\s+(giving|sending)\s+(away\s+)?\$?\d[\d,]*\s+(to\s+)?(random|the\s+first|everyone)/i, category: "Generosity Scam", severity: "medium" },
    { pattern: /who\s+(needs?|wants?)\s+\$?\d[\d,]*\s*\??/i, category: "Generosity Scam", severity: "medium" },
    { pattern: /drop\s+your\s+(cash\s*app|venmo|zelle|paypal)\s*(tag|handle|below|username)?/i, category: "Cash Tag Harvesting", severity: "medium" }
  ],

  // Suspicious TLDs for link checking
  SUSPICIOUS_TLDS: [
    ".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".icu", ".cam", ".rest", ".surf",
    ".click", ".link", ".fun", ".monster", ".sbs", ".cfd",
    ".quest", ".beauty", ".hair", ".skin", ".makeup",
    ".loan", ".date", ".racing", ".win", ".bid", ".stream",
    ".download", ".review", ".accountant", ".science", ".party",
    ".faith", ".cricket", ".gdn", ".ren", ".kim", ".pw",
    ".cc", ".ws", ".cyou", ".cfd", ".boats", ".bond"
  ],

  // URL shorteners — always suspicious in social media posts
  URL_SHORTENERS: [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "shorturl.at",
    "rb.gy", "cutt.ly", "t.ly", "v.gd", "qr.ae", "clck.ru",
    "s.id", "rotf.lol", "shorturl.asia", "tiny.cc",
    "short.io", "rebrand.ly", "soo.gd", "u.to", "zpr.io",
    "3.ly", "bc.vc", "dfrn.us", "mcaf.ee", "0rz.tw",
    "snip.ly", "cli.re", "tr.im", "trib.al", "dlvr.it",
    "fbit.co", "zii.bz", "ouo.io", "shrtco.de"
  ],

  // Trusted domains that should NOT trigger external link warnings
  TRUSTED_EXTERNAL: [
    "youtube.com", "youtu.be", "google.com", "wikipedia.org",
    "amazon.com", "ebay.com", "etsy.com", "spotify.com",
    "apple.com", "netflix.com", "github.com", "medium.com",
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com",
    "washingtonpost.com", "theguardian.com", "imgur.com",
    "giphy.com", "tenor.com", "pinterest.com", "flickr.com",
    "vimeo.com", "soundcloud.com", "twitch.tv", "discord.gg",
    "discord.com", "linkedin.com", "reddit.com", "tumblr.com",
    "tiktok.com", "snapchat.com", "whatsapp.com",
    "microsoft.com", "adobe.com", "wordpress.com", "wordpress.org",
    "shopify.com", "paypal.com", "stripe.com", "zoom.us",
    "dropbox.com", "drive.google.com", "docs.google.com",
    "stackoverflow.com", "npmjs.com", "pypi.org",
    "bbc.co.uk", "theverge.com", "techcrunch.com", "wired.com",
    "arstechnica.com", "engadget.com", "mashable.com",
    "nbcnews.com", "abcnews.go.com", "cbsnews.com", "foxnews.com",
    "apnews.com", "usatoday.com", "wsj.com", "ft.com",
    "bloomberg.com", "cnbc.com", "forbes.com", "businessinsider.com",
    "weather.com", "yelp.com", "tripadvisor.com", "zillow.com",
    "craigslist.org", "target.com", "walmart.com", "bestbuy.com",
    "costco.com", "homedepot.com", "lowes.com", "wayfair.com",
    "goodreads.com", "imdb.com", "rottentomatoes.com"
  ],

  // =========================================================
  // COMBO RULES — multiple low-signal hits escalate severity
  // When a post matches multiple categories, these rules fire.
  // =========================================================
  COMBO_RULES: [
    // MLM/income scam combos — individually low, together suspicious
    { require: ["Bio Link Solicitation", "Income Claim"], escalate: "medium", label: "Income Pitch + Bio Link" },
    { require: ["Bio Link Solicitation", "Emoji Pattern"], escalate: "medium", label: "Bio Link + Hype Emojis" },
    { require: ["DM Solicitation", "Income Claim"], escalate: "medium", label: "Income Pitch + DM Request" },
    { require: ["DM Solicitation", "Fake Scarcity"], escalate: "medium", label: "DM + Fake Scarcity" },
    { require: ["MLM/Pyramid", "Income Claim"], escalate: "high", label: "MLM + Income Claims" },
    { require: ["Engagement Farming", "Income Claim"], escalate: "high", label: "Engagement Farm + Income" },
    { require: ["Engagement Farming", "Guru Scam"], escalate: "high", label: "Engagement Farm + Guru" },

    // Platform migration combos — moving off-platform is suspicious with money context
    { require: ["Platform Migration", "Income Claim"], escalate: "high", label: "Off-Platform + Income" },
    { require: ["Platform Migration", "Romance Scam"], escalate: "high", label: "Off-Platform + Romance" },
    { require: ["Platform Migration", "Contact Solicitation"], escalate: "medium", label: "Off-Platform + Contact Request" },
    { require: ["Platform Migration", "Investment Scam"], escalate: "high", label: "Off-Platform + Investment" },

    // Pig butchering progression combos
    { require: ["Wrong Number Opener", "Pig Butchering Probe"], escalate: "high", label: "Wrong Number → Investment Probe" },
    { require: ["Wrong Number Scam", "Platform Migration"], escalate: "high", label: "Wrong Number → Off-Platform" },
    { require: ["Pig Butchering Probe", "Pig Butchering Deposit"], escalate: "critical", label: "Pig Butchering: Probe → Deposit" },

    // Romance + money combos
    { require: ["Romance Scam", "Advance Fee Scam"], escalate: "critical", label: "Romance + Fee Request" },
    { require: ["Romance Manipulation", "Platform Migration"], escalate: "high", label: "Romance + Off-Platform" },
    { require: ["Romance Manipulation", "WhatsApp Solicitation"], escalate: "high", label: "Romance + WhatsApp" },

    // Fake urgency amplifiers
    { require: ["Fake Scarcity", "Income Claim"], escalate: "high", label: "Scarcity + Income Claims" },
    { require: ["FOMO Manipulation", "Investment Scam"], escalate: "high", label: "FOMO + Investment" },
    { require: ["Fake Time Pressure", "Prize Scam"], escalate: "high", label: "Time Pressure + Prize" },
    { require: ["Urgency Manipulation", "Advance Fee Scam"], escalate: "high", label: "Urgency + Fee" },

    // Emoji + text combos
    { require: ["Emoji Pattern", "Income Claim"], escalate: "medium", label: "Hype Emojis + Income" },
    { require: ["Emoji Pattern", "Fake Cash Giveaway"], escalate: "high", label: "Hype Emojis + Giveaway" },
    { require: ["Emoji Pattern", "Cash Flipping Scam"], escalate: "high", label: "Hype Emojis + Cash Flip" },

    // Generosity + harvesting
    { require: ["Generosity Scam", "Cash Tag Harvesting"], escalate: "high", label: "Fake Generosity + Cash Tag Collection" },

    // Task scam progression
    { require: ["Task Scam", "Platform Migration"], escalate: "high", label: "Task Scam + Off-Platform" },
    { require: ["Task Scam", "Task Scam Deposit Trap"], escalate: "critical", label: "Task Scam → Deposit Trap" },

    // Recovery scam targeting victims
    { require: ["Recovery Scam", "Contact Solicitation"], escalate: "critical", label: "Recovery Scam + Contact" },
    { require: ["Recovery Scam", "WhatsApp Solicitation"], escalate: "critical", label: "Recovery Scam + WhatsApp" },

    // Music platform scam combos
    { require: ["Fake Engagement Service", "DM Solicitation"], escalate: "high", label: "Fake Plays + DM Request" },
    { require: ["Fake Engagement Service", "Platform Migration"], escalate: "high", label: "Fake Plays + Off-Platform" },
    { require: ["Fake Label Scout", "Platform Migration"], escalate: "high", label: "Fake Label + Off-Platform" },
    { require: ["Fake Label Scout", "Advance Fee Scam"], escalate: "critical", label: "Fake Label + Fee Request" },
    { require: ["Fake Discovery Promise", "Advance Fee Scam"], escalate: "critical", label: "Fake Discovery + Fee" }
  ],

  /**
   * Initialize the scanner — detect platform and start observing.
   */
  init() {
    this._platform = this._detectPlatform();
    if (!this._platform) return; // Not a social media site

    // Initial scan after a short delay (let content load)
    setTimeout(() => this.scanAllPosts(), 1500);

    // For SPA-heavy platforms, do additional delayed scans as content loads
    if (this._platform.genericFallback) {
      setTimeout(() => this.scanAllPosts(), 4000);
      setTimeout(() => this.scanAllPosts(), 8000);
    }

    // Observe feed for new posts
    this._startObserver();
  },

  /**
   * Detect which social media platform we're on.
   */
  _detectPlatform() {
    const hostname = window.location.hostname.toLowerCase();
    for (const [name, config] of Object.entries(this.PLATFORMS)) {
      if (config.hosts.some(h => hostname === h || hostname.endsWith("." + h))) {
        return { name, ...config };
      }
    }
    return null;
  },

  /**
   * Scan all visible posts on the page.
   * Three-tier fallback:
   *   1. Platform-specific selectors (reliable on Facebook, X, etc.)
   *   2. Semantic role selectors (article, listitem, etc.)
   *   3. Deep content scan — finds text blocks & links regardless of DOM structure
   *      (essential for React SPAs like SoundCloud with opaque class names)
   */
  scanAllPosts() {
    if (!this._platform || !this._enabled) return;

    let posts = document.querySelectorAll(this._platform.postSelector);

    // Tier 2: semantic role selectors
    if (posts.length === 0 && this._platform.genericFallback) {
      posts = document.querySelectorAll(
        'article, [role="article"], [role="comment"], [role="listitem"]'
      );
    }

    // Tier 3: deep content scan — find text blocks around links and in content areas
    if (posts.length === 0 && this._platform.genericFallback) {
      posts = this._findContentBlocks();
    }

    for (const post of posts) {
      this._scanPost(post);
    }
  },

  /**
   * Deep content block finder — works on any DOM structure.
   * Finds scannable content by locating:
   *   1. Containers around external links (scams always link out)
   *   2. Text-heavy elements (comments, descriptions, bios)
   * Returns an array of DOM elements to scan as "posts".
   */
  _findContentBlocks() {
    const blocks = [];
    const seen = new WeakSet();
    const root = document.querySelector("main") || document.body;

    // Strategy 1: Find containers around external links
    // Scam content almost always contains outbound links
    const links = root.querySelectorAll("a[href]");
    for (const link of links) {
      const href = link.getAttribute("href") || "";
      // Skip anchors, relative paths, and javascript: links
      if (!href || href.startsWith("#") || href.startsWith("javascript:")) continue;

      // Skip same-site links
      try {
        const url = new URL(href, window.location.href);
        if (url.hostname === window.location.hostname) continue;
      } catch (e) {
        continue;
      }

      // Walk up to find the nearest block-level container
      const container = link.closest("div, li, p, section, article, td, blockquote") || link.parentElement;
      if (!container || seen.has(container)) continue;

      const text = (container.innerText || "").trim();
      if (text.length < 15 || text.length > 5000) continue;

      seen.add(container);
      blocks.push(container);
    }

    // Strategy 2: Find text-heavy elements that look like user content
    // Target elements whose class names suggest comments, descriptions, bios
    const contentSelectors = [
      '[class*="comment"]', '[class*="Comment"]',
      '[class*="description"]', '[class*="Description"]',
      '[class*="bio"]', '[class*="Bio"]',
      '[class*="message"]', '[class*="Message"]',
      '[class*="caption"]', '[class*="Caption"]',
      '[class*="body"]', '[class*="Body"]',
      '[class*="text"]', '[class*="Text"]',
      '[class*="content"]', '[class*="Content"]',
      '[class*="chat"]', '[class*="Chat"]',
      '[class*="inbox"]', '[class*="Inbox"]',
      '[class*="conversation"]', '[class*="Conversation"]',
      '[class*="reply"]', '[class*="Reply"]'
    ].join(", ");

    try {
      const textEls = root.querySelectorAll(contentSelectors);
      for (const el of textEls) {
        if (seen.has(el)) continue;
        const text = (el.innerText || "").trim();
        if (text.length < 25 || text.length > 3000) continue;
        // Skip big container divs — we want leaf-ish content elements
        if (el.children.length > 20) continue;
        // Skip nav/header/footer
        if (el.closest("nav, header, footer")) continue;
        seen.add(el);
        blocks.push(el);
      }
    } catch (e) {
      // Selector may fail in edge cases — continue
    }

    return blocks;
  },

  /**
   * Scan a single post element for scam indicators.
   */
  _scanPost(postElement) {
    // Skip already-scanned posts
    if (this._scannedPosts.has(postElement)) return;
    this._scannedPosts.add(postElement);

    // Skip posts that already have our warning
    if (postElement.querySelector('.scaim-post-warning')) return;

    const text = (postElement.innerText || "").trim();
    const minLen = (this._platform && this._platform.minTextLength) || 20;
    if (text.length < minLen) return; // Too short to analyze

    const findings = [];

    // 1. Check text against scam patterns (with platform filtering)
    this._checkPatterns(text, findings);

    // 2. Check links within the post (neurotic mode)
    this._checkLinks(postElement, findings);

    // 3. Check for suspicious emoji patterns (common in scam posts)
    this._checkEmojiPatterns(text, findings);

    // 4. Check for contact info solicitation
    this._checkContactSolicitation(text, findings);

    // 5. Run combo detection — escalate when multiple low-signal patterns combine
    this._checkCombinations(findings);

    // 6. If findings, inject inline warning and notify page-level analyzer
    if (findings.length > 0) {
      this._injectWarning(postElement, findings);

      // Notify the page-level analyzer so the banner + popup reflect social media scam findings
      if (typeof ScaimAnalyzer !== "undefined") {
        ScaimAnalyzer.addSocialFindings(findings);
      }
    }
  },

  /**
   * Check post text against scam patterns.
   * Optimized: skips platform-specific patterns not for current platform,
   * and pre-lowercases text once to avoid repeated case conversion in regexes.
   */
  _checkPatterns(text, findings) {
    const platformName = this._platform ? this._platform.name : null;
    // Normalize to defeat zero-width char and homoglyph evasion
    const normalizedText = typeof TextNormalizer !== "undefined" ? TextNormalizer.normalize(text) : text;
    const lowerText = normalizedText.toLowerCase();

    for (const sp of this.SCAM_PATTERNS) {
      // Platform filter: skip patterns locked to other platforms
      if (sp.platforms && (!platformName || !sp.platforms.includes(platformName))) continue;

      // Run the regex against normalized text
      if (sp.pattern.test(normalizedText)) {
        findings.push({
          severity: sp.severity,
          category: sp.category
        });
      }
    }
  },

  /**
   * Neurotic link checking — flag external links, shorteners, mismatches, etc.
   */
  _checkLinks(postElement, findings) {
    const links = postElement.querySelectorAll(this._platform.linkSelector);
    let externalLinkCount = 0;
    let shortenerCount = 0;
    const isHighParanoia = this._platform.paranoia === "high";

    for (const link of links) {
      const href = (link.getAttribute("href") || "").toLowerCase();
      const displayText = (link.textContent || "").trim().toLowerCase();

      // Skip empty, anchor-only, or javascript links
      if (!href || href.startsWith("#") || href.startsWith("javascript:")) continue;

      // Handle protocol-relative and relative URLs
      let url;
      try {
        url = new URL(href, window.location.href);
      } catch (e) {
        continue;
      }

      const linkHost = url.hostname.toLowerCase();

      // Skip same-platform links
      if (this._platform.hosts.some(h => linkHost === h || linkHost.endsWith("." + h))) continue;

      // Skip Facebook's internal redirect links (l.facebook.com, lm.facebook.com)
      if (/^l(m)?\.facebook\.com$/i.test(linkHost)) continue;

      // Skip tracking/CDN subdomains of the platform
      if (this._platform.name === "facebook" && linkHost.endsWith(".fbcdn.net")) continue;
      if (this._platform.name === "x" && linkHost.endsWith(".twimg.com")) continue;
      if (this._platform.name === "instagram" && linkHost.endsWith(".cdninstagram.com")) continue;

      // Skip the platform's own URL shortener (e.g., t.co for X)
      const ownShortener = this._platform.ownShortener;
      if (ownShortener && (linkHost === ownShortener || linkHost === "www." + ownShortener)) continue;

      externalLinkCount++;

      // ---- URL Shortener Detection ----
      const isShortener = this.URL_SHORTENERS.some(s => linkHost === s || linkHost === "www." + s);
      if (isShortener) {
        shortenerCount++;
        findings.push({
          severity: "medium",
          category: "Shortened URL",
          detail: `Link uses URL shortener (${linkHost}) — the real destination is hidden`
        });
      }

      // ---- Suspicious TLD ----
      for (const tld of this.SUSPICIOUS_TLDS) {
        if (linkHost.endsWith(tld)) {
          findings.push({
            severity: "medium",
            category: "Suspicious Link",
            detail: `Link to ${linkHost} uses suspicious domain extension "${tld}"`
          });
          break;
        }
      }

      // ---- Href Spoofing (display text looks like a URL but doesn't match) ----
      const urlPattern = /^(https?:\/\/)?[\w.-]+\.\w{2,}/;
      if (urlPattern.test(displayText)) {
        const displayDomain = displayText.replace(/^https?:\/\//, "").split("/")[0];
        if (displayDomain !== linkHost && !linkHost.endsWith("." + displayDomain)) {
          findings.push({
            severity: "high",
            category: "Link Spoofing",
            detail: `Link shows "${displayText.substring(0, 40)}" but goes to "${linkHost}"`
          });
        }
      }

      // ---- Dangerous file extensions ----
      const pathname = url.pathname.toLowerCase();
      const dangerousExts = [".exe", ".scr", ".bat", ".msi", ".vbs", ".cmd", ".ps1", ".hta", ".jar", ".apk"];
      for (const ext of dangerousExts) {
        if (pathname.endsWith(ext)) {
          findings.push({
            severity: "high",
            category: "Dangerous Download",
            detail: `Link points to executable file (${ext})`
          });
          break;
        }
      }

      // ---- Blocklist check ----
      if (typeof DomainLists !== "undefined" && DomainLists._loaded) {
        const blockMatch = DomainLists.isBlocked(linkHost);
        if (blockMatch) {
          findings.push({
            severity: "critical",
            category: "Blocklisted Link",
            detail: `Link goes to blocklisted domain: ${linkHost} (${blockMatch.category})`
          });
        }
      }

      // ---- Flag untrusted external links in high-paranoia mode ----
      if (isHighParanoia && !isShortener) {
        const isTrusted = this.TRUSTED_EXTERNAL.some(d => linkHost === d || linkHost === "www." + d || linkHost.endsWith("." + d));
        if (!isTrusted) {
          // Only flag if the link text looks clickbait-y or the domain seems random
          const clickbaitTerms = /click\s+here|learn\s+more|check\s+this|see\s+more|visit|open|view/i;
          const hasClickbait = clickbaitTerms.test(displayText);
          const isRandomDomain = /^[a-z0-9]{8,}\./.test(linkHost); // Long random subdomain
          const hasNumbers = /\d{3,}/.test(linkHost); // Numbers in domain

          if (hasClickbait || isRandomDomain || hasNumbers) {
            findings.push({
              severity: "low",
              category: "Unverified External Link",
              detail: `Links to unknown external site: ${linkHost}`
            });
          }
        }
      }
    }

    // ---- Multiple external links in one post ----
    if (externalLinkCount >= 3) {
      findings.push({
        severity: "medium",
        category: "Multiple External Links",
        detail: `Post contains ${externalLinkCount} external links — unusual for a normal post`
      });
    }

    // ---- Multiple URL shorteners ----
    if (shortenerCount >= 2) {
      findings.push({
        severity: "high",
        category: "Multiple Shortened URLs",
        detail: `Post uses ${shortenerCount} different URL shorteners — highly suspicious`
      });
    }
  },

  /**
   * Check for suspicious emoji patterns common in scam posts.
   * Scam posts on FB/IG often use excessive money/fire/rocket emojis.
   */
  _checkEmojiPatterns(text, findings) {
    // Money-related emojis
    const moneyEmojis = (text.match(/[\u{1F4B0}\u{1F4B5}\u{1F4B4}\u{1F4B6}\u{1F4B7}\u{1F4B8}\u{1F911}\u{1F4B2}]/gu) || []).length;
    // Rocket/fire/gem (crypto pump signals)
    const hypeEmojis = (text.match(/[\u{1F680}\u{1F525}\u{1F4A5}\u{1F48E}\u{2B06}\u{FE0F}\u{1F4C8}\u{1F31F}\u{2728}]/gu) || []).length;
    // Warning/alert emojis
    const alertEmojis = (text.match(/[\u{26A0}\u{FE0F}\u{1F6A8}\u{274C}\u{2757}\u{203C}\u{FE0F}\u{1F6D1}]/gu) || []).length;

    const totalSuspicious = moneyEmojis + hypeEmojis + alertEmojis;

    if (moneyEmojis >= 3 || totalSuspicious >= 5) {
      findings.push({
        severity: "low",
        category: "Emoji Pattern",
        detail: `Excessive money/hype emojis (${totalSuspicious}) — common in scam and spam posts`
      });
    }

    // Alert emojis combined with text patterns
    if (alertEmojis >= 2) {
      const hasUrgency = /urgent|important|warning|attention|breaking|alert/i.test(text);
      if (hasUrgency) {
        findings.push({
          severity: "medium",
          category: "Fake Urgency",
          detail: "Alert emojis combined with urgency language — common social media scare tactic"
        });
      }
    }
  },

  /**
   * Check for posts trying to collect contact info.
   */
  _checkContactSolicitation(text, findings) {
    // Phone number in post (not from a business page context)
    const phonePattern = /\b\+?\d{1,3}[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/;
    const hasPhone = phonePattern.test(text);

    // Email in post
    const emailPattern = /\b[\w.+-]+@[\w-]+\.[\w.]+\b/;
    const hasEmail = emailPattern.test(text);

    // Combination of contact methods with suspicious context
    if (hasPhone || hasEmail) {
      const suspiciousContext = /contact\s+(me|us)|send\s+message|reach\s+(me|out)|dm\s+me|whatsapp|telegram|for\s+(more\s+)?(info|details)/i;
      if (suspiciousContext.test(text)) {
        findings.push({
          severity: "low",
          category: "Contact Solicitation",
          detail: `Post shares ${hasPhone ? "phone number" : "email"} with contact request — may be legitimate, but common in scams`
        });
      }
    }

    // WhatsApp/Telegram number in post
    if (/whatsapp.*\+?\d{10,}|\+?\d{10,}.*whatsapp/i.test(text)) {
      findings.push({
        severity: "medium",
        category: "WhatsApp Solicitation",
        detail: "Post shares a WhatsApp number — scammers use this to move conversations off-platform"
      });
    }
  },

  /**
   * Combo detection: when multiple individually-low-signal findings appear
   * in the same post, escalate severity. Also escalates when many low-severity
   * findings accumulate (even without specific combo rules).
   */
  _checkCombinations(findings) {
    if (findings.length < 2) return;

    const categories = new Set(findings.map(f => f.category));
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };

    // Check named combo rules
    for (const rule of this.COMBO_RULES) {
      const allPresent = rule.require.every(cat => categories.has(cat));
      if (allPresent) {
        findings.push({
          severity: rule.escalate,
          category: "Pattern Combination",
          detail: `Combined signals: ${rule.label}`
        });
      }
    }

    // Generic escalation: many low-severity findings = something's off
    const lowCount = findings.filter(f => f.severity === "low").length;
    const uniqueLowCategories = new Set(findings.filter(f => f.severity === "low").map(f => f.category)).size;

    if (uniqueLowCategories >= 4) {
      findings.push({
        severity: "high",
        category: "Multiple Indicators",
        detail: `${uniqueLowCategories} different warning categories detected — the combination is highly suspicious`
      });
    } else if (uniqueLowCategories >= 3) {
      findings.push({
        severity: "medium",
        category: "Multiple Indicators",
        detail: `${uniqueLowCategories} different warning categories detected — worth extra caution`
      });
    }
  },

  /**
   * Inject an inline warning on a suspicious post.
   */
  _injectWarning(postElement, findings) {
    // Determine overall severity (validated against known values)
    const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
    const maxSeverity = findings.reduce((max, f) => {
      const sev = severityOrder[f.severity] ? f.severity : "low";
      return severityOrder[sev] > severityOrder[max] ? sev : max;
    }, "low");

    // Build warning message
    const categories = [...new Set(findings.map(f => f.category))];
    const details = findings.filter(f => f.detail).map(f => f.detail);

    // Compose a concise but informative message
    let message;
    if (categories.length === 1) {
      message = `ScAIm: ${categories[0]}`;
      if (details.length > 0) message += ` — ${details[0]}`;
    } else {
      message = `ScAIm detected ${findings.length} warning(s): ${categories.slice(0, 3).join(", ")}`;
      if (categories.length > 3) message += ` +${categories.length - 3} more`;
    }

    // Create warning element
    const warning = document.createElement("div");
    warning.className = `scaim-post-warning scaim-post-${maxSeverity}`;
    warning.innerHTML = `
      <div class="scaim-post-warning-content">
        <span class="scaim-post-warning-icon">${maxSeverity === "critical" ? "\u{1F6D1}" : maxSeverity === "high" ? "\u{1F6A8}" : "\u26A0\uFE0F"}</span>
        <span class="scaim-post-warning-text">${this._escapeHtml(message)}</span>
        <button class="scaim-post-warning-dismiss" title="Dismiss">\u2715</button>
      </div>
    `;

    // Dismiss handler
    const dismissBtn = warning.querySelector(".scaim-post-warning-dismiss");
    dismissBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      warning.style.maxHeight = "0";
      warning.style.opacity = "0";
      warning.style.padding = "0";
      warning.style.margin = "0";
      setTimeout(() => warning.remove(), 300);
    });

    // Insert warning at the top of the post
    try {
      postElement.style.position = postElement.style.position || "relative";
      postElement.insertBefore(warning, postElement.firstChild);
    } catch (e) {
      // Some frameworks prevent direct insertion; try parent
      try {
        postElement.parentElement.insertBefore(warning, postElement);
      } catch (e2) {
        // Give up silently
      }
    }
  },

  /**
   * Start MutationObserver on the feed container.
   */
  _startObserver() {
    if (this._observer) this._observer.disconnect();

    const feedContainer = document.querySelector(this._platform.feedSelector) || document.body;

    let debounceTimer = null;
    this._observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => this.scanAllPosts(), 800);
    });

    this._observer.observe(feedContainer, {
      childList: true,
      subtree: true
    });
  },

  /**
   * Check if the current page is a social media site.
   */
  isSocialMedia() {
    return this._platform !== null;
  },

  /**
   * Escape HTML for safe injection.
   */
  _escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }
};
