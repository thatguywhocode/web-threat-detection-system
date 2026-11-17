/**
 * SentinelCore — SOC Event Service (v1.0)
 *
 * Implements querying, filtering, pagination, and duplicate-prevention
 * for normalized SOC SecurityEvent records.
 */

const { getSecurityEventModel } = require("./eventModel");
const { adaptScanResult } = require("./eventAdapter");

/**
 * Escapes regex special characters to prevent ReDoS or regex injection attacks
 */
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Sanitizes and validates incoming query filters
 */
function parseAndSanitizeFilters(query = {}) {
  const filter = {};

  // 1. Verdict filter (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)
  if (query.verdict && typeof query.verdict === "string") {
    const rawVerdicts = query.verdict.split(",").map(v => v.trim().toUpperCase());
    const validVerdicts = ["SAFE", "SUSPICIOUS", "MALICIOUS", "INCONCLUSIVE"];
    const matched = rawVerdicts.filter(v => validVerdicts.includes(v));

    if (matched.length === 1) {
      filter.verdict = matched[0];
    } else if (matched.length > 1) {
      filter.verdict = { $in: matched };
    }
  }

  // 2. Severity filter (LOW, MEDIUM, HIGH)
  if (query.severity && typeof query.severity === "string") {
    const rawSeverities = query.severity.split(",").map(s => s.trim().toUpperCase());
    const validSeverities = ["LOW", "MEDIUM", "HIGH"];
    const matched = rawSeverities.filter(s => validSeverities.includes(s));

    if (matched.length === 1) {
      filter.severity = matched[0];
    } else if (matched.length > 1) {
      filter.severity = { $in: matched };
    }
  }

  // 3. Target filter (sanitized partial substring match)
  if (query.target && typeof query.target === "string" && query.target.trim()) {
    const safeTarget = escapeRegex(query.target.trim().slice(0, 150));
    filter.target = { $regex: safeTarget, $options: "i" };
  }

  // 4. Date range filter (from / to or startDate / endDate)
  const fromRaw = query.from || query.startDate;
  const toRaw = query.to || query.endDate;
  const dateConditions = {};

  if (fromRaw) {
    const fromDate = new Date(fromRaw);
    if (!isNaN(fromDate.getTime())) {
      dateConditions.$gte = fromDate;
    }
  }

  if (toRaw) {
    const toDate = new Date(toRaw);
    if (!isNaN(toDate.getTime())) {
      dateConditions.$lte = toDate;
    }
  }

  if (Object.keys(dateConditions).length > 0) {
    filter.timestamp = dateConditions;
  }

  return filter;
}

/**
 * Records a completed scan into the SOC SecurityEvent store with duplicate elimination
 *
 * @param {Object} scanInput - { target, url, html }
 * @param {Object} scanResult - { analysis, risk, virusTotal }
 * @param {Object} [options={}] - { clientIp, userAgent, timestamp }
 * @returns {Promise<{ event: Object, isDuplicate: boolean }>}
 */
async function recordScanEvent(scanInput, scanResult, options = {}) {
  const model = getSecurityEventModel();
  const eventDoc = adaptScanResult(scanInput, scanResult, options);

  // Check for duplicate scan reference
  const existing = await model.findOne({ scanReference: eventDoc.scanReference });
  if (existing) {
    return {
      event: existing,
      isDuplicate: true
    };
  }

  try {
    const created = await model.create(eventDoc);
    return {
      event: created,
      isDuplicate: false
    };
  } catch (err) {
    // Graceful handling of concurrent duplicate insertion error (code 11000)
    if (err.code === 11000) {
      const raceExisting = await model.findOne({ scanReference: eventDoc.scanReference });
      if (raceExisting) {
        return {
          event: raceExisting,
          isDuplicate: true
        };
      }
    }
    throw err;
  }
}

/**
 * Retrieves paginated, sorted, and filtered SOC SecurityEvents
 *
 * @param {Object} query - Express query params
 * @returns {Promise<Object>} Paginated events result
 */
async function getEvents(query = {}) {
  const model = getSecurityEventModel();
  const filter = parseAndSanitizeFilters(query);

  // Pagination parameters
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(query.limit, 10) || 20));
  const skip = (page - 1) * limit;

  // Sorting: default to newest first
  let sort = { timestamp: -1 };
  if (query.sort === "oldest" || query.sort === "timestamp") {
    sort = { timestamp: 1 };
  } else if (query.sort === "score_desc" || query.sort === "-riskScore") {
    sort = { riskScore: -1 };
  } else if (query.sort === "score_asc" || query.sort === "riskScore") {
    sort = { riskScore: 1 };
  }

  const [total, events] = await Promise.all([
    model.countDocuments(filter),
    model.find(filter)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .lean()
  ]);

  const totalPages = Math.ceil(total / limit) || 1;

  return {
    success: true,
    total,
    page,
    limit,
    totalPages,
    hasMore: page < totalPages,
    events
  };
}

/**
 * Retrieves a single event by eventId or Mongo _id
 */
async function getEventById(id) {
  const model = getSecurityEventModel();
  if (!id || typeof id !== "string") return null;

  const event = await model.findOne({
    $or: [{ eventId: id }, { _id: id }]
  });

  return event || null;
}

/**
 * Computes high-level aggregated SOC telemetry statistics
 */
async function getEventStats() {
  const model = getSecurityEventModel();
  const [total, safe, suspicious, malicious, inconclusive] = await Promise.all([
    model.countDocuments({}),
    model.countDocuments({ verdict: "SAFE" }),
    model.countDocuments({ verdict: "SUSPICIOUS" }),
    model.countDocuments({ verdict: "MALICIOUS" }),
    model.countDocuments({ verdict: "INCONCLUSIVE" })
  ]);

  return {
    total,
    totalEvents: total,
    byVerdict: {
      safe,
      suspicious,
      malicious,
      inconclusive
    }
  };
}

/**
 * Utility for test resets
 */
async function clearAllEvents() {
  const model = getSecurityEventModel();
  if (typeof model.deleteMany === "function") {
    return model.deleteMany({});
  }
}

module.exports = {
  recordScanEvent,
  getEvents,
  getEventById,
  getEventStats,
  parseAndSanitizeFilters,
  clearAllEvents
};
