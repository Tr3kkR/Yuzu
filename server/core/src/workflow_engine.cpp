#include "workflow_engine.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <chrono>
#include <map>
#include <random>
#include <shared_mutex>

namespace yuzu::server {

// ── Helpers ──────────────────────────────────────────────────────────────────

namespace {

int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string col_text(sqlite3_stmt* stmt, int col) {
    auto p = sqlite3_column_text(stmt, col);
    return p ? std::string(reinterpret_cast<const char*>(p)) : std::string{};
}

std::string gen_id() {
    static std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    auto hi = dist(rng);
    auto lo = dist(rng);
    char buf[33];
    std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                  static_cast<unsigned long long>(hi),
                  static_cast<unsigned long long>(lo));
    return std::string(buf, 32);
}

/// Minimal YAML value extractor — matches the pattern used across all Yuzu stores.
std::string extract_yaml_value(const std::string& yaml, const std::string& key) {
    auto search = key + ":";
    auto pos = yaml.find(search);
    while (pos != std::string::npos) {
        if (pos > 0 && yaml[pos - 1] != '\n' && yaml[pos - 1] != ' ' && yaml[pos - 1] != '\t') {
            pos = yaml.find(search, pos + 1);
            continue;
        }
        auto vstart = pos + search.size();
        while (vstart < yaml.size() && (yaml[vstart] == ' ' || yaml[vstart] == '\t'))
            ++vstart;
        if (vstart >= yaml.size() || yaml[vstart] == '\n')
            return {};
        auto eol = yaml.find('\n', vstart);
        if (eol == std::string::npos)
            eol = yaml.size();
        auto val = yaml.substr(vstart, eol - vstart);
        while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
            val.pop_back();
        if (val.size() >= 2 &&
            ((val.front() == '"' && val.back() == '"') ||
             (val.front() == '\'' && val.back() == '\''))) {
            val = val.substr(1, val.size() - 2);
        }
        if (val == ">" || val == "|")
            return {};
        return val;
    }
    return {};
}

/// Extract a YAML sequence block into a list of maps representing steps.
/// Each step is a mapping under "- instruction:" within the steps: block.
struct RawStep {
    std::string instruction;
    std::string condition;
    std::string retry_count;
    std::string retry_delay;
    std::string foreach_source;
    std::string label;
    std::string on_failure;
};

std::vector<RawStep> extract_steps(const std::string& yaml) {
    std::vector<RawStep> steps;

    // Find the "steps:" block
    auto steps_pos = yaml.find("steps:");
    if (steps_pos == std::string::npos)
        return steps;

    // Find the start of the list (first "- " after "steps:")
    auto search_start = yaml.find('\n', steps_pos);
    if (search_start == std::string::npos)
        return steps;

    // Determine the indentation level of list items
    RawStep current;
    bool in_step = false;
    std::string::size_type pos = search_start + 1;

    while (pos < yaml.size()) {
        auto eol = yaml.find('\n', pos);
        if (eol == std::string::npos)
            eol = yaml.size();

        auto line = yaml.substr(pos, eol - pos);
        // Strip trailing CR
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        // Check if this is a non-indented line (end of steps block)
        if (!line.empty() && line[0] != ' ' && line[0] != '\t' && line[0] != '-') {
            if (in_step)
                steps.push_back(current);
            break;
        }

        // Trim leading whitespace to find content
        auto trimmed = line;
        auto first_non_space = trimmed.find_first_not_of(" \t");
        if (first_non_space != std::string::npos)
            trimmed = trimmed.substr(first_non_space);

        // New list item starts with "- "
        if (trimmed.starts_with("- ")) {
            if (in_step)
                steps.push_back(current);
            current = RawStep{};
            in_step = true;
            // The rest after "- " might be "instruction: ..."
            auto rest = trimmed.substr(2);
            auto colon = rest.find(':');
            if (colon != std::string::npos) {
                auto key = rest.substr(0, colon);
                auto val = rest.substr(colon + 1);
                // Trim val
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    val.erase(val.begin());
                while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                    val.pop_back();
                // Strip quotes
                if (val.size() >= 2 &&
                    ((val.front() == '"' && val.back() == '"') ||
                     (val.front() == '\'' && val.back() == '\''))) {
                    val = val.substr(1, val.size() - 2);
                }
                if (key == "instruction") current.instruction = val;
                else if (key == "label") current.label = val;
                else if (key == "condition" || key == "if") current.condition = val;
                else if (key == "foreach") current.foreach_source = val;
                else if (key == "onFailure") current.on_failure = val;
            }
        } else if (in_step && !trimmed.empty()) {
            // Continuation of current step (key: value pair)
            auto colon = trimmed.find(':');
            if (colon != std::string::npos) {
                auto key = trimmed.substr(0, colon);
                auto val = trimmed.substr(colon + 1);
                while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
                    val.erase(val.begin());
                while (!val.empty() && (val.back() == ' ' || val.back() == '\t' || val.back() == '\r'))
                    val.pop_back();
                if (val.size() >= 2 &&
                    ((val.front() == '"' && val.back() == '"') ||
                     (val.front() == '\'' && val.back() == '\''))) {
                    val = val.substr(1, val.size() - 2);
                }
                if (key == "instruction") current.instruction = val;
                else if (key == "label") current.label = val;
                else if (key == "condition" || key == "if") current.condition = val;
                else if (key == "retryCount") current.retry_count = val;
                else if (key == "retryDelay") current.retry_delay = val;
                else if (key == "foreach") current.foreach_source = val;
                else if (key == "onFailure") current.on_failure = val;
            }
        }

        pos = eol + 1;
    }
    // Push last step if still in one
    if (in_step)
        steps.push_back(current);

    return steps;
}

} // namespace

// ── Construction / destruction ──────────────────────────────────────────────

WorkflowEngine::WorkflowEngine(const std::filesystem::path& db_path) {
    int rc = sqlite3_open(db_path.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("WorkflowEngine: failed to open DB {}: {}", db_path.string(),
                      sqlite3_errmsg(db_));
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        return;
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA busy_timeout=5000;", nullptr, nullptr, nullptr);

    create_tables();
    spdlog::info("WorkflowEngine: opened {}", db_path.string());
}

WorkflowEngine::~WorkflowEngine() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool WorkflowEngine::is_open() const {
    return db_ != nullptr;
}

void WorkflowEngine::create_tables() {
    const char* ddl = R"(
        CREATE TABLE IF NOT EXISTS workflows (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            yaml_source TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS workflow_steps (
            workflow_id TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            instruction_id TEXT NOT NULL,
            condition TEXT NOT NULL DEFAULT '',
            retry_count INTEGER NOT NULL DEFAULT 0,
            retry_delay_seconds INTEGER NOT NULL DEFAULT 5,
            foreach_source TEXT NOT NULL DEFAULT '',
            label TEXT NOT NULL DEFAULT '',
            on_failure TEXT NOT NULL DEFAULT 'abort',
            PRIMARY KEY (workflow_id, step_index),
            FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS workflow_executions (
            id TEXT PRIMARY KEY,
            workflow_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            agent_ids_json TEXT NOT NULL DEFAULT '[]',
            started_at INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER,
            current_step INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (workflow_id) REFERENCES workflows(id)
        );

        CREATE TABLE IF NOT EXISTS workflow_step_results (
            execution_id TEXT NOT NULL,
            step_index INTEGER NOT NULL,
            instruction_id TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            result_json TEXT NOT NULL DEFAULT '{}',
            started_at INTEGER NOT NULL DEFAULT 0,
            completed_at INTEGER,
            attempt INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (execution_id, step_index),
            FOREIGN KEY (execution_id) REFERENCES workflow_executions(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_wf_exec_workflow ON workflow_executions(workflow_id);
        CREATE INDEX IF NOT EXISTS idx_wf_step_results_exec ON workflow_step_results(execution_id);
    )";
    char* err = nullptr;
    if (sqlite3_exec(db_, ddl, nullptr, nullptr, &err) != SQLITE_OK) {
        spdlog::error("WorkflowEngine: DDL failed: {}", err ? err : "unknown");
        sqlite3_free(err);
    }
}

std::string WorkflowEngine::generate_id() const {
    return gen_id();
}

// ── Workflow CRUD ───────────────────────────────────────────────────────────

std::expected<std::string, std::string> WorkflowEngine::create_workflow(
    const std::string& yaml_source) {

    // Validate kind
    auto kind = extract_yaml_value(yaml_source, "kind");
    if (!kind.empty() && kind != "Workflow") {
        return std::unexpected("expected kind: Workflow, got: " + kind);
    }

    auto name = extract_yaml_value(yaml_source, "displayName");
    if (name.empty())
        name = extract_yaml_value(yaml_source, "name");
    if (name.empty())
        return std::unexpected("workflow name is required (metadata.displayName or metadata.name)");

    auto description = extract_yaml_value(yaml_source, "description");

    // Parse steps
    auto raw_steps = extract_steps(yaml_source);
    if (raw_steps.empty())
        return std::unexpected("workflow must have at least one step");

    std::vector<WorkflowStep> steps;
    for (int i = 0; i < static_cast<int>(raw_steps.size()); ++i) {
        auto& rs = raw_steps[i];
        if (rs.instruction.empty())
            return std::unexpected("step " + std::to_string(i) + " missing instruction ID");

        WorkflowStep s;
        s.index = i;
        s.instruction_id = rs.instruction;
        s.condition = rs.condition;
        s.foreach_source = rs.foreach_source;
        s.label = rs.label;
        s.on_failure = rs.on_failure.empty() ? "abort" : rs.on_failure;

        if (!rs.retry_count.empty()) {
            try { s.retry_count = std::stoi(rs.retry_count); }
            catch (...) {}
        }
        if (!rs.retry_delay.empty()) {
            try { s.retry_delay_seconds = std::stoi(rs.retry_delay); }
            catch (...) {}
        }

        steps.push_back(std::move(s));
    }

    auto id = generate_id();
    auto now = now_epoch();

    std::unique_lock lock(mtx_);

    const char* sql = "INSERT INTO workflows (id, name, description, yaml_source, created_at, updated_at) "
                      "VALUES (?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));
    }
    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, yaml_source.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, now);
    sqlite3_bind_int64(stmt, 6, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return std::unexpected(std::string("insert failed: ") + sqlite3_errmsg(db_));
    }

    store_steps(id, steps);

    spdlog::info("WorkflowEngine: created workflow '{}' ({}), {} steps", name, id, steps.size());
    return id;
}

std::vector<Workflow> WorkflowEngine::list_workflows(const WorkflowQuery& q) const {
    std::shared_lock lock(mtx_);
    std::vector<Workflow> result;

    std::string sql = "SELECT id, name, description, yaml_source, created_at, updated_at "
                      "FROM workflows";
    std::vector<std::string> binds;
    if (!q.name_filter.empty()) {
        sql += " WHERE name LIKE ?";
        binds.push_back("%" + q.name_filter + "%");
    }
    sql += " ORDER BY created_at DESC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    int idx = 1;
    for (auto& b : binds)
        sqlite3_bind_text(stmt, idx++, b.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx, q.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Workflow w;
        w.id = col_text(stmt, 0);
        w.name = col_text(stmt, 1);
        w.description = col_text(stmt, 2);
        w.yaml_source = col_text(stmt, 3);
        w.created_at = sqlite3_column_int64(stmt, 4);
        w.updated_at = sqlite3_column_int64(stmt, 5);
        w.steps = load_steps(w.id);
        result.push_back(std::move(w));
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<Workflow> WorkflowEngine::get_workflow(const std::string& id) const {
    std::shared_lock lock(mtx_);

    const char* sql = "SELECT id, name, description, yaml_source, created_at, updated_at "
                      "FROM workflows WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    Workflow w;
    w.id = col_text(stmt, 0);
    w.name = col_text(stmt, 1);
    w.description = col_text(stmt, 2);
    w.yaml_source = col_text(stmt, 3);
    w.created_at = sqlite3_column_int64(stmt, 4);
    w.updated_at = sqlite3_column_int64(stmt, 5);
    sqlite3_finalize(stmt);

    w.steps = load_steps(w.id);
    return w;
}

bool WorkflowEngine::delete_workflow(const std::string& id) {
    std::unique_lock lock(mtx_);

    // Delete steps first (CASCADE should handle it, but be explicit)
    {
        const char* sql = "DELETE FROM workflow_steps WHERE workflow_id = ?";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    const char* sql = "DELETE FROM workflows WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return false;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    int changes = sqlite3_changes(db_);
    sqlite3_finalize(stmt);
    return changes > 0;
}

// ── Step storage helpers ────────────────────────────────────────────────────

void WorkflowEngine::store_steps(const std::string& workflow_id,
                                  const std::vector<WorkflowStep>& steps) {
    const char* sql = "INSERT INTO workflow_steps "
                      "(workflow_id, step_index, instruction_id, condition, "
                      "retry_count, retry_delay_seconds, foreach_source, label, on_failure) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    for (const auto& s : steps) {
        // Defense-in-depth: reject steps with empty instruction_id at storage level
        if (s.instruction_id.empty()) {
            spdlog::warn("WorkflowEngine: skipping step {} with empty instruction_id", s.index);
            continue;
        }
        sqlite3_reset(stmt);
        sqlite3_bind_text(stmt, 1, workflow_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, s.index);
        sqlite3_bind_text(stmt, 3, s.instruction_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, s.condition.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 5, s.retry_count);
        sqlite3_bind_int(stmt, 6, s.retry_delay_seconds);
        sqlite3_bind_text(stmt, 7, s.foreach_source.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 8, s.label.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 9, s.on_failure.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
}

std::vector<WorkflowStep> WorkflowEngine::load_steps(const std::string& workflow_id) const {
    std::vector<WorkflowStep> steps;
    const char* sql = "SELECT step_index, instruction_id, condition, retry_count, "
                      "retry_delay_seconds, foreach_source, label, on_failure "
                      "FROM workflow_steps WHERE workflow_id = ? ORDER BY step_index";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return steps;

    sqlite3_bind_text(stmt, 1, workflow_id.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WorkflowStep s;
        s.index = sqlite3_column_int(stmt, 0);
        s.instruction_id = col_text(stmt, 1);
        s.condition = col_text(stmt, 2);
        s.retry_count = sqlite3_column_int(stmt, 3);
        s.retry_delay_seconds = sqlite3_column_int(stmt, 4);
        s.foreach_source = col_text(stmt, 5);
        s.label = col_text(stmt, 6);
        s.on_failure = col_text(stmt, 7);
        steps.push_back(std::move(s));
    }
    sqlite3_finalize(stmt);
    return steps;
}

// ── Execution helpers ───────────────────────────────────────────────────────

void WorkflowEngine::create_step_result(const std::string& execution_id,
                                          const WorkflowStepResult& sr) {
    const char* sql = "INSERT OR REPLACE INTO workflow_step_results "
                      "(execution_id, step_index, instruction_id, status, result_json, "
                      "started_at, completed_at, attempt) "
                      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, sr.step_index);
    sqlite3_bind_text(stmt, 3, sr.instruction_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, sr.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, sr.result_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, sr.started_at);
    sqlite3_bind_int64(stmt, 7, sr.completed_at);
    sqlite3_bind_int(stmt, 8, sr.attempt);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void WorkflowEngine::update_step_result(const std::string& execution_id, int step_index,
                                          const std::string& status,
                                          const std::string& result_json) {
    const char* sql = "UPDATE workflow_step_results SET status = ?, result_json = ?, "
                      "completed_at = ? WHERE execution_id = ? AND step_index = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return;

    auto now = now_epoch();
    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, result_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, now);
    sqlite3_bind_text(stmt, 4, execution_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, step_index);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

void WorkflowEngine::update_execution_status(const std::string& id, const std::string& status,
                                               int current_step) {
    std::string sql = "UPDATE workflow_executions SET status = ?";
    if (status == "completed" || status == "failed" || status == "cancelled")
        sql += ", completed_at = " + std::to_string(now_epoch());
    if (current_step >= 0)
        sql += ", current_step = " + std::to_string(current_step);
    sql += " WHERE id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return;

    sqlite3_bind_text(stmt, 1, status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

std::vector<std::string> WorkflowEngine::expand_foreach(
    const std::string& foreach_source, const std::string& prev_result_json) const {
    std::vector<std::string> items;
    try {
        auto result = nlohmann::json::parse(prev_result_json, nullptr, false);
        if (result.is_discarded())
            return items;

        // If foreach_source names a field, extract array from that field
        nlohmann::json arr;
        if (result.contains(foreach_source) && result[foreach_source].is_array()) {
            arr = result[foreach_source];
        } else if (result.is_array()) {
            arr = result;
        } else {
            // Treat the whole result as a single item
            items.push_back(prev_result_json);
            return items;
        }

        for (const auto& item : arr) {
            items.push_back(item.dump());
        }
    } catch (const std::exception&) {
        // Parse failure — single item
        items.push_back(prev_result_json);
    }
    return items;
}

// ── Execute workflow ────────────────────────────────────────────────────────

std::expected<std::string, std::string> WorkflowEngine::execute(
    const std::string& workflow_id,
    const std::vector<std::string>& agent_ids,
    StepDispatchFn dispatch_fn,
    ConditionEvalFn condition_fn) {

    if (!dispatch_fn)
        return std::unexpected("dispatch function is required");

    // Load workflow
    auto workflow = get_workflow(workflow_id);
    if (!workflow)
        return std::unexpected("workflow not found: " + workflow_id);

    if (workflow->steps.empty())
        return std::unexpected("workflow has no steps");

    auto exec_id = generate_id();
    auto now = now_epoch();
    nlohmann::json agent_ids_arr = agent_ids;

    // Create execution record
    {
        std::unique_lock lock(mtx_);
        const char* sql = "INSERT INTO workflow_executions "
                          "(id, workflow_id, status, agent_ids_json, started_at, current_step) "
                          "VALUES (?, ?, 'running', ?, ?, 0)";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            return std::unexpected(std::string("prepare failed: ") + sqlite3_errmsg(db_));

        auto agent_str = agent_ids_arr.dump();
        sqlite3_bind_text(stmt, 1, exec_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, workflow_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, agent_str.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, now);
        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE)
            return std::unexpected(std::string("exec insert failed: ") + sqlite3_errmsg(db_));

        // Pre-create step result records
        for (const auto& step : workflow->steps) {
            WorkflowStepResult sr;
            sr.step_index = step.index;
            sr.instruction_id = step.instruction_id;
            sr.status = "pending";
            sr.started_at = 0;
            create_step_result(exec_id, sr);
        }
    }

    // Execute steps sequentially
    std::string prev_result_json = "{}";
    bool execution_failed = false;

    for (const auto& step : workflow->steps) {
        // Check if execution was cancelled
        {
            auto exec = get_execution(exec_id);
            if (exec && exec->status == "cancelled") {
                execution_failed = true;
                break;
            }
        }

        // Update current step
        {
            std::unique_lock lock(mtx_);
            update_execution_status(exec_id, "running", step.index);
        }

        // Evaluate condition if present
        if (!step.condition.empty() && condition_fn) {
            // Parse previous result into fields map
            std::map<std::string, std::string> fields;
            try {
                auto prev = nlohmann::json::parse(prev_result_json, nullptr, false);
                if (!prev.is_discarded() && prev.is_object()) {
                    for (auto& [k, v] : prev.items()) {
                        fields["result." + k] = v.is_string() ? v.get<std::string>() : v.dump();
                    }
                }
            } catch (...) {}

            if (!condition_fn(step.condition, fields)) {
                // Condition not met — skip step
                {
                    std::unique_lock lock(mtx_);
                    update_step_result(exec_id, step.index, "skipped", R"({"reason":"condition not met"})");
                }
                spdlog::info("WorkflowEngine: step {} skipped (condition: {})", step.index, step.condition);
                continue;
            }
        }

        // Mark step as running
        {
            std::unique_lock lock(mtx_);
            WorkflowStepResult sr;
            sr.step_index = step.index;
            sr.instruction_id = step.instruction_id;
            sr.status = "running";
            sr.started_at = now_epoch();
            create_step_result(exec_id, sr);
        }

        // Determine dispatch items (foreach expansion)
        std::vector<std::string> dispatch_params;
        if (!step.foreach_source.empty()) {
            dispatch_params = expand_foreach(step.foreach_source, prev_result_json);
        } else {
            dispatch_params.push_back("{}");
        }

        // Dispatch with retry logic
        bool step_succeeded = false;
        std::string step_result;

        for (int attempt = 1; attempt <= (step.retry_count + 1); ++attempt) {
            // For foreach, aggregate results
            nlohmann::json foreach_results = nlohmann::json::array();
            bool foreach_failed = false;

            for (const auto& params : dispatch_params) {
                auto dispatch_result = dispatch_fn(step.instruction_id,
                                                    agent_ids_arr.dump(), params);
                if (dispatch_result) {
                    foreach_results.push_back(
                        nlohmann::json::parse(*dispatch_result, nullptr, false));
                } else {
                    foreach_failed = true;
                    foreach_results.push_back(
                        nlohmann::json({{"error", dispatch_result.error()}}));
                }
            }

            if (!foreach_failed) {
                step_succeeded = true;
                step_result = dispatch_params.size() == 1
                    ? foreach_results[0].dump()
                    : foreach_results.dump();
                break;
            }

            // Retry if attempts remain
            if (attempt <= step.retry_count) {
                spdlog::warn("WorkflowEngine: step {} attempt {}/{} failed, retrying in {}s",
                             step.index, attempt, step.retry_count + 1, step.retry_delay_seconds);
                std::this_thread::sleep_for(
                    std::chrono::seconds(step.retry_delay_seconds));
            } else {
                step_result = foreach_results.dump();
            }

            // Update attempt count
            {
                std::unique_lock lock(mtx_);
                const char* sql = "UPDATE workflow_step_results SET attempt = ? "
                                  "WHERE execution_id = ? AND step_index = ?";
                sqlite3_stmt* stmt = nullptr;
                if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) == SQLITE_OK) {
                    sqlite3_bind_int(stmt, 1, attempt);
                    sqlite3_bind_text(stmt, 2, exec_id.c_str(), -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int(stmt, 3, step.index);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                }
            }
        }

        // Record step result
        {
            std::unique_lock lock(mtx_);
            update_step_result(exec_id, step.index,
                               step_succeeded ? "success" : "failed",
                               step_result);
        }

        if (step_succeeded) {
            prev_result_json = step_result;
        } else {
            // Handle failure based on on_failure policy
            if (step.on_failure == "continue") {
                spdlog::warn("WorkflowEngine: step {} failed, continuing (on_failure=continue)",
                             step.index);
                prev_result_json = step_result;
            } else if (step.on_failure == "skip_remaining") {
                spdlog::warn("WorkflowEngine: step {} failed, skipping remaining steps",
                             step.index);
                // Mark remaining steps as skipped
                std::unique_lock lock(mtx_);
                for (const auto& remaining : workflow->steps) {
                    if (remaining.index > step.index) {
                        update_step_result(exec_id, remaining.index, "skipped",
                                           R"({"reason":"previous step failed"})");
                    }
                }
                execution_failed = true;
                break;
            } else {
                // "abort" — default
                spdlog::error("WorkflowEngine: step {} failed, aborting workflow", step.index);
                // Mark remaining steps as skipped
                std::unique_lock lock(mtx_);
                for (const auto& remaining : workflow->steps) {
                    if (remaining.index > step.index) {
                        update_step_result(exec_id, remaining.index, "skipped",
                                           R"({"reason":"workflow aborted"})");
                    }
                }
                execution_failed = true;
                break;
            }
        }
    }

    // Finalize execution
    {
        std::unique_lock lock(mtx_);
        update_execution_status(exec_id,
                                execution_failed ? "failed" : "completed");
    }

    spdlog::info("WorkflowEngine: execution {} {}", exec_id,
                 execution_failed ? "failed" : "completed");
    return exec_id;
}

// ── Execution queries ───────────────────────────────────────────────────────

std::optional<WorkflowExecution> WorkflowEngine::get_execution(const std::string& id) const {
    std::shared_lock lock(mtx_);

    const char* sql = "SELECT id, workflow_id, status, agent_ids_json, started_at, "
                      "completed_at, current_step FROM workflow_executions WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::nullopt;

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    WorkflowExecution exec;
    exec.id = col_text(stmt, 0);
    exec.workflow_id = col_text(stmt, 1);
    exec.status = col_text(stmt, 2);
    exec.agent_ids_json = col_text(stmt, 3);
    exec.started_at = sqlite3_column_int64(stmt, 4);
    exec.completed_at = sqlite3_column_int64(stmt, 5);
    exec.current_step = sqlite3_column_int(stmt, 6);
    sqlite3_finalize(stmt);

    // Load step results
    const char* sr_sql = "SELECT step_index, instruction_id, status, result_json, "
                         "started_at, completed_at, attempt "
                         "FROM workflow_step_results WHERE execution_id = ? ORDER BY step_index";
    if (sqlite3_prepare_v2(db_, sr_sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            WorkflowStepResult sr;
            sr.step_index = sqlite3_column_int(stmt, 0);
            sr.instruction_id = col_text(stmt, 1);
            sr.status = col_text(stmt, 2);
            sr.result_json = col_text(stmt, 3);
            sr.started_at = sqlite3_column_int64(stmt, 4);
            sr.completed_at = sqlite3_column_int64(stmt, 5);
            sr.attempt = sqlite3_column_int(stmt, 6);
            exec.step_results.push_back(std::move(sr));
        }
        sqlite3_finalize(stmt);
    }

    return exec;
}

std::vector<WorkflowExecution> WorkflowEngine::list_executions(
    const std::string& workflow_id, int limit) const {
    std::shared_lock lock(mtx_);
    std::vector<WorkflowExecution> result;

    std::string sql = "SELECT id, workflow_id, status, agent_ids_json, started_at, "
                      "completed_at, current_step FROM workflow_executions";
    if (!workflow_id.empty())
        sql += " WHERE workflow_id = ?";
    sql += " ORDER BY started_at DESC LIMIT ?";

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
        return result;

    int idx = 1;
    if (!workflow_id.empty())
        sqlite3_bind_text(stmt, idx++, workflow_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        WorkflowExecution exec;
        exec.id = col_text(stmt, 0);
        exec.workflow_id = col_text(stmt, 1);
        exec.status = col_text(stmt, 2);
        exec.agent_ids_json = col_text(stmt, 3);
        exec.started_at = sqlite3_column_int64(stmt, 4);
        exec.completed_at = sqlite3_column_int64(stmt, 5);
        exec.current_step = sqlite3_column_int(stmt, 6);
        result.push_back(std::move(exec));
    }
    sqlite3_finalize(stmt);
    return result;
}

std::expected<void, std::string> WorkflowEngine::cancel_execution(const std::string& id) {
    std::unique_lock lock(mtx_);

    // Verify it exists and is running
    const char* check_sql = "SELECT status FROM workflow_executions WHERE id = ?";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, check_sql, -1, &stmt, nullptr) != SQLITE_OK)
        return std::unexpected("db error");

    sqlite3_bind_text(stmt, 1, id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::unexpected("execution not found");
    }
    auto status = col_text(stmt, 0);
    sqlite3_finalize(stmt);

    if (status != "pending" && status != "running")
        return std::unexpected("execution is already " + status);

    update_execution_status(id, "cancelled");
    return {};
}

} // namespace yuzu::server
