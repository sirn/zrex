use std::cmp::Reverse;
use std::collections::HashSet;
use std::env;
use std::io::{self, Write};
use std::time::Duration;

use crossterm::{
    cursor::MoveTo,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute, queue,
    style::{Attribute, Color, Print, SetAttribute, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use fuzzy_matcher::{FuzzyMatcher, skim::SkimMatcherV2};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::{
    ManageScope, ManageTarget, ProgramState, SessionChoice, StyleRole, StyledSpan, Target,
    format_warnings_summary, styled_scope_row, styled_server_row,
};
use crate::config::DetachKey;
use crate::text::truncate_with_ellipsis;

const MIN_INPUT_WIDTH: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Feedback {
    pub(super) text: String,
    pub(super) is_error: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FocusTarget {
    pub(super) server_name: String,
    pub(super) session_id: String,
    pub(super) block_id: String,
}

pub(super) enum StepEvent {
    Cancel,
    Selected(Selection),
    Discovery(super::ServerDiscoveryEvent),
    DiscoveryFinished,
    FlushPending,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum AttachSelection {
    Existing(usize),
    NewSession {
        server_index: usize,
        label: Option<String>,
    },
    NewWindow {
        session_index: usize,
        label: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Selection {
    Attach(AttachSelection),
    Rename { target: ManageTarget, label: String },
    Kill { target: ManageTarget },
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Cancel,
    Selected(Selection),
}

impl From<Outcome> for StepEvent {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Cancel => Self::Cancel,
            Outcome::Selected(selection) => Self::Selected(selection),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum EditOutcome {
    Changed,
    Moved,
    Unhandled,
}

#[derive(Default)]
struct TextInput {
    chars: Vec<char>,
    cursor: usize,
}

impl TextInput {
    fn from_text(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let cursor = chars.len();
        Self { chars, cursor }
    }

    fn text(&self) -> String {
        self.chars.iter().collect()
    }

    fn trimmed_non_empty(&self) -> Option<String> {
        let text = self.text();
        let trimmed = text.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> EditOutcome {
        match (code, modifiers) {
            (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
                if self.chars.is_empty() {
                    return EditOutcome::Moved;
                }
                self.chars.clear();
                self.cursor = 0;
                EditOutcome::Changed
            }
            (KeyCode::Backspace, _) if self.cursor > 0 => {
                self.cursor -= 1;
                self.chars.remove(self.cursor);
                EditOutcome::Changed
            }
            (KeyCode::Delete, _) if self.cursor < self.chars.len() => {
                self.chars.remove(self.cursor);
                EditOutcome::Changed
            }
            (KeyCode::Left, KeyModifiers::ALT | KeyModifiers::CONTROL)
            | (KeyCode::Char('b'), KeyModifiers::ALT) => {
                self.cursor = word_left(&self.chars, self.cursor);
                EditOutcome::Moved
            }
            (KeyCode::Right, KeyModifiers::ALT | KeyModifiers::CONTROL)
            | (KeyCode::Char('f'), KeyModifiers::ALT) => {
                self.cursor = word_right(&self.chars, self.cursor);
                EditOutcome::Moved
            }
            (KeyCode::Home, _) | (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                self.cursor = 0;
                EditOutcome::Moved
            }
            (KeyCode::End, _) | (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
                self.cursor = self.chars.len();
                EditOutcome::Moved
            }
            (KeyCode::Left, _) => {
                self.cursor = self.cursor.saturating_sub(1);
                EditOutcome::Moved
            }
            (KeyCode::Right, _) => {
                self.cursor = (self.cursor + 1).min(self.chars.len());
                EditOutcome::Moved
            }
            (KeyCode::Char(ch), mods)
                if !ch.is_control() && mods.difference(KeyModifiers::SHIFT).is_empty() =>
            {
                self.chars.insert(self.cursor, ch);
                self.cursor += 1;
                EditOutcome::Changed
            }
            _ => EditOutcome::Unhandled,
        }
    }

    fn visible(&self, max_width: usize) -> (String, usize) {
        let mut start = self.cursor;
        let mut offset = 0;
        while start > 0 {
            let next = offset + self.chars[start - 1].width().unwrap_or(0);
            if next > max_width {
                break;
            }
            offset = next;
            start -= 1;
        }
        let mut remaining = max_width;
        let displayed: String = self.chars[start..]
            .iter()
            .copied()
            .take_while(|ch| {
                let width = ch.width().unwrap_or(0);
                if width > remaining {
                    return false;
                }
                remaining -= width;
                true
            })
            .collect();
        (displayed, offset)
    }
}

const SCOPE_COLUMN_WIDTH: usize = 9;

struct ManageChoice {
    target: ManageTarget,
    display: String,
    detail: String,
    initial_label: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttachView {
    All,
    Agents,
}

enum Mode {
    Attach,
    NewSession {
        server_index: usize,
        first: usize,
        input: TextInput,
    },
    NewWindow {
        session_index: usize,
        first: usize,
        input: TextInput,
    },
    Rename {
        choices: Vec<ManageChoice>,
        selected: usize,
        first: usize,
        input: TextInput,
        dirty: bool,
    },
    Kill {
        choices: Vec<ManageChoice>,
        selected: usize,
        first: usize,
    },
}

pub(super) struct PickerState {
    targets: Vec<Target>,
    sessions: Vec<SessionChoice>,
    servers: Vec<String>,
    labels: Vec<String>,
    matcher: SkimMatcherV2,
    attach_input: TextInput,
    matches: Vec<(usize, Vec<usize>)>,
    attach_selected: usize,
    attach_first: usize,
    view: AttachView,
    mode: Mode,
    feedback: Option<Feedback>,
    discovery_warnings: Vec<String>,
    pending_focus: Option<FocusTarget>,
    refreshing: bool,
    loading: Vec<String>,
    loading_is_refresh: bool,
    detach_key: DetachKey,
}

impl PickerState {
    pub(super) fn new(
        targets: Vec<Target>,
        sessions: Vec<SessionChoice>,
        servers: Vec<String>,
    ) -> Self {
        let labels = targets.iter().map(Target::search_text).collect();
        let mut state = Self {
            targets,
            sessions,
            servers,
            labels,
            matcher: SkimMatcherV2::default(),
            attach_input: TextInput::default(),
            matches: Vec::new(),
            attach_selected: 0,
            attach_first: 0,
            view: AttachView::All,
            mode: Mode::Attach,
            feedback: None,
            discovery_warnings: Vec::new(),
            pending_focus: None,
            refreshing: false,
            loading: Vec::new(),
            loading_is_refresh: false,
            detach_key: DetachKey::default(),
        };
        state.recompute_matches();
        state
    }

    pub(super) fn set_detach_key(&mut self, detach_key: DetachKey) {
        self.detach_key = detach_key;
    }

    pub(super) fn is_attach_mode(&self) -> bool {
        matches!(self.mode, Mode::Attach)
    }

    pub(super) fn set_loading(&mut self, servers: Vec<String>, is_refresh: bool) {
        self.loading = servers;
        self.loading_is_refresh = is_refresh;
        self.refreshing = !self.loading.is_empty();
    }

    pub(super) fn finish_loading(&mut self) {
        self.loading.clear();
        self.refreshing = false;
        self.pending_focus = None;
    }

    #[cfg(test)]
    pub(super) fn set_feedback(&mut self, feedback: Feedback) {
        self.feedback = Some(feedback);
    }

    /// Resets the picker after returning from an attached block: clears any
    /// prior filter query, returns to attach mode, focuses `focus` if it is
    /// already present (and remembers it until the user interacts so a
    /// background refresh can focus a newly created session or window), and
    /// shows a refreshing status banner until background discovery completes.
    pub(super) fn reset_after_attach(
        &mut self,
        focus: Option<FocusTarget>,
        feedback: Option<Feedback>,
    ) {
        self.attach_input = TextInput::default();
        self.mode = Mode::Attach;
        self.recompute_matches();
        if let Some(target) = &focus
            && let Some(pos) = self.find_focus_target(target)
        {
            self.attach_selected = pos;
        }
        self.pending_focus = focus;
        self.feedback = feedback;
        self.discovery_warnings.clear();
        self.loading.clear();
        self.loading_is_refresh = true;
        self.refreshing = true;
    }

    /// Applies an incremental server discovery update while preserving the
    /// user's active filter query, selection, and pending focus (until either
    /// the target arrives, the user interacts, or all servers finish).
    pub(super) fn apply_server_update(
        &mut self,
        targets: Vec<Target>,
        sessions: Vec<SessionChoice>,
        servers: Vec<String>,
        warning: Option<String>,
        still_loading: bool,
    ) {
        self.update_entries(targets, sessions, Some(servers), still_loading);
        if let Some(warning) = warning {
            self.discovery_warnings.push(warning);
        }
    }

    /// Applies a full server-discovery refresh while preserving the user's
    /// active filter query and selection (or focusing `pending_focus` if the
    /// user has not navigated since returning from attach).
    #[cfg(test)]
    pub(super) fn apply_discovery(
        &mut self,
        targets: Vec<Target>,
        sessions: Vec<SessionChoice>,
        servers: Vec<String>,
        warning: Option<Feedback>,
    ) {
        self.update_entries(targets, sessions, Some(servers), false);
        self.loading.clear();
        self.refreshing = false;
        if self.feedback.is_none() {
            self.feedback = warning;
        }
    }

    pub(super) fn refresh(
        &mut self,
        targets: Vec<Target>,
        sessions: Vec<SessionChoice>,
        feedback: Feedback,
    ) {
        self.pending_focus = None;
        self.discovery_warnings.clear();
        self.mode = Mode::Attach;
        let still_loading = !self.loading.is_empty();
        self.update_entries(targets, sessions, None, still_loading);
        self.feedback = Some(feedback);
    }

    fn update_entries(
        &mut self,
        targets: Vec<Target>,
        sessions: Vec<SessionChoice>,
        servers: Option<Vec<String>>,
        still_loading: bool,
    ) {
        let prev = self.selected_identity();
        let prev_selected = self.attach_selected;

        self.targets = targets;
        self.sessions = sessions;
        if let Some(servers) = servers {
            self.servers = servers;
        }
        self.labels = self.targets.iter().map(Target::search_text).collect();
        self.recompute_matches();

        if let Some(focus) = self.pending_focus.as_ref()
            && let Some(pos) = self.find_focus_target(focus)
        {
            self.attach_selected = pos;
            self.pending_focus = None;
        } else {
            if !still_loading {
                self.pending_focus = None;
            }
            if let Some((prev_server, prev_key)) = prev {
                if let Some(pos) = self.matches.iter().position(|&(index, _)| {
                    let target = &self.targets[index];
                    self.is_on_server(target, &prev_server) && prev_key.matches_block(target)
                }) {
                    self.attach_selected = pos;
                } else if let Some(pos) = self.matches.iter().position(|&(index, _)| {
                    let target = &self.targets[index];
                    self.is_on_server(target, &prev_server) && prev_key.matches_window(target)
                }) {
                    self.attach_selected = pos;
                } else if !self.matches.is_empty() {
                    self.attach_selected = prev_selected.min(self.matches.len() - 1);
                }
            } else if !self.matches.is_empty() {
                self.attach_selected = prev_selected.min(self.matches.len() - 1);
            }
        }

        if !still_loading {
            self.refreshing = false;
        }
    }

    fn is_on_server(&self, target: &Target, server_name: &str) -> bool {
        self.servers
            .get(target.server_index)
            .is_some_and(|name| name == server_name)
    }

    fn selected_identity(&self) -> Option<(String, super::TargetKey)> {
        let &(index, _) = self.matches.get(self.attach_selected)?;
        let target = &self.targets[index];
        let server = self.servers.get(target.server_index)?.clone();
        Some((server, target.key()))
    }

    fn find_focus_target(&self, focus: &FocusTarget) -> Option<usize> {
        self.matches.iter().position(|&(index, _)| {
            let target = &self.targets[index];
            self.is_on_server(target, &focus.server_name)
                && target.session_id == focus.session_id
                && target.block_id == focus.block_id
        })
    }

    fn has_agents(&self) -> bool {
        self.targets.iter().any(Target::is_agent)
    }

    fn set_view(&mut self, view: AttachView) {
        if self.view == view {
            return;
        }
        let prev = self.selected_identity();
        self.view = view;
        self.recompute_matches();
        if let Some((prev_server, prev_key)) = prev
            && let Some(pos) = self.matches.iter().position(|&(index, _)| {
                let target = &self.targets[index];
                self.is_on_server(target, &prev_server) && prev_key.matches_block(target)
            })
        {
            self.attach_selected = pos;
        }
    }

    fn recompute_matches(&mut self) {
        let pattern = self.attach_input.text();
        let agents_only = self.view == AttachView::Agents;
        let mut ranked: Vec<_> = self
            .labels
            .iter()
            .enumerate()
            .filter(|&(index, _)| !agents_only || self.targets[index].is_agent())
            .filter_map(|(index, label)| {
                self.matcher
                    .fuzzy_indices(label, &pattern)
                    .map(|(score, indices)| {
                        let status_rank = if agents_only {
                            self.targets[index].status_rank()
                        } else {
                            0
                        };
                        (Reverse(score), status_rank, index, indices)
                    })
            })
            .collect();
        ranked.sort_unstable_by_key(|&(score, status_rank, index, _)| (score, status_rank, index));
        self.matches = ranked
            .into_iter()
            .map(|(_, _, index, indices)| (index, indices))
            .collect();
        self.attach_selected = 0;
        self.attach_first = 0;
    }

    fn default_server_index(&self) -> usize {
        self.matches
            .get(self.attach_selected)
            .map(|&(index, _)| self.targets[index].server_index)
            .unwrap_or(0)
    }

    fn default_session_index(&self) -> usize {
        self.matches
            .get(self.attach_selected)
            .map(|&(index, _)| self.targets[index].session_index)
            .unwrap_or(0)
    }

    fn session_counts(&self, session_index: usize) -> (usize, usize) {
        let mut windows = HashSet::new();
        let mut blocks = 0;
        for target in &self.targets {
            if target.session_index == session_index {
                windows.insert(target.window_id.as_str());
                blocks += 1;
            }
        }
        (windows.len(), blocks)
    }

    fn build_manage_choices(&self, for_kill: bool) -> Option<(Vec<ManageChoice>, usize)> {
        if self.sessions.is_empty() {
            return None;
        }
        if self.targets.is_empty() {
            let choices = self
                .sessions
                .iter()
                .map(|session| ManageChoice {
                    target: ManageTarget {
                        server_index: session.server_index,
                        session_id: session.session_id.clone(),
                        scope: ManageScope::Session,
                    },
                    display: session.display_name(),
                    detail: "(no windows)".to_owned(),
                    initial_label: session.label.clone(),
                })
                .collect();
            return Some((choices, 0));
        }

        let &(target_index, _) = self.matches.get(self.attach_selected)?;
        let target = &self.targets[target_index];
        let session = &self.sessions[target.session_index];
        let session_display = session.display_name();
        let (win_count, blk_count) = self.session_counts(target.session_index);

        let session_detail = if for_kill {
            format!(
                "({win_count} {}, {blk_count} {})",
                plural(win_count, "window", "windows"),
                plural(blk_count, "block", "blocks"),
            )
        } else {
            String::new()
        };

        let window_display = match &target.window_label {
            Some(label) => format!("{session_display} / {} {label}", target.window_number),
            None => format!("{session_display} / {}", target.window_number),
        };
        let window_detail = if for_kill {
            format!(
                "({} {})",
                target.window_block_count,
                plural(target.window_block_count, "block", "blocks"),
            )
        } else {
            String::new()
        };

        let block_index_text = if target.window_block_count > 1 {
            format!("{}.{}", target.window_number, target.block_number)
        } else {
            target.window_number.to_string()
        };
        let block_name = target
            .block_label
            .as_deref()
            .or(target.process.as_deref())
            .or((!target.block_raw_label.is_empty()).then_some(target.block_raw_label.as_str()));
        let block_display = match block_name {
            Some(name) => format!("{session_display} / {block_index_text} {name}"),
            None => format!("{session_display} / {block_index_text}"),
        };
        let block_detail = if for_kill && target.window_block_count == 1 {
            "(closes window)".to_owned()
        } else {
            String::new()
        };

        let mut choices = vec![
            ManageChoice {
                target: ManageTarget {
                    server_index: target.server_index,
                    session_id: target.session_id.clone(),
                    scope: ManageScope::Session,
                },
                display: session_display,
                detail: session_detail,
                initial_label: session.label.clone(),
            },
            ManageChoice {
                target: ManageTarget {
                    server_index: target.server_index,
                    session_id: target.session_id.clone(),
                    scope: ManageScope::Window(target.window_id.clone()),
                },
                display: window_display,
                detail: window_detail,
                initial_label: target.window_label.clone().unwrap_or_default(),
            },
            ManageChoice {
                target: ManageTarget {
                    server_index: target.server_index,
                    session_id: target.session_id.clone(),
                    scope: ManageScope::Block(target.block_id.clone()),
                },
                display: block_display,
                detail: block_detail,
                initial_label: target.block_label.clone().unwrap_or_default(),
            },
        ];

        // Also include any empty sessions so they remain manageable even when
        // other sessions have open windows.
        for (idx, other) in self.sessions.iter().enumerate() {
            if idx == target.session_index {
                continue;
            }
            if !self.targets.iter().any(|t| t.session_index == idx) {
                choices.push(ManageChoice {
                    target: ManageTarget {
                        server_index: other.server_index,
                        session_id: other.session_id.clone(),
                        scope: ManageScope::Session,
                    },
                    display: other.display_name(),
                    detail: "(no windows)".to_owned(),
                    initial_label: other.label.clone(),
                });
            }
        }

        let default_selected = if target.window_block_count > 1 { 2 } else { 1 };
        Some((choices, default_selected))
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Option<Outcome> {
        self.feedback = None;
        self.discovery_warnings.clear();
        self.pending_focus = None;
        if is_quit_key(code, modifiers, self.detach_key) {
            return Some(Outcome::Cancel);
        }
        match &mut self.mode {
            Mode::Attach => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    if self.view == AttachView::Agents {
                        self.set_view(AttachView::All);
                        None
                    } else {
                        Some(Outcome::Cancel)
                    }
                }
                (KeyCode::Char('g'), KeyModifiers::CONTROL) => {
                    let next = match self.view {
                        AttachView::All => AttachView::Agents,
                        AttachView::Agents => AttachView::All,
                    };
                    self.set_view(next);
                    None
                }
                (KeyCode::Enter, _) if !self.matches.is_empty() => {
                    Some(Outcome::Selected(Selection::Attach(
                        AttachSelection::Existing(self.matches[self.attach_selected].0),
                    )))
                }
                (KeyCode::Char('n'), KeyModifiers::CONTROL) if !self.servers.is_empty() => {
                    let server_index = self.default_server_index();
                    self.mode = Mode::NewSession {
                        server_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Char('t'), KeyModifiers::CONTROL) if !self.sessions.is_empty() => {
                    let session_index = self.default_session_index();
                    self.mode = Mode::NewWindow {
                        session_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Char('r'), KeyModifiers::CONTROL) => {
                    if let Some((choices, selected)) = self.build_manage_choices(false) {
                        let input = TextInput::from_text(&choices[selected].initial_label);
                        self.mode = Mode::Rename {
                            choices,
                            selected,
                            first: 0,
                            input,
                            dirty: false,
                        };
                    }
                    None
                }
                (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                    if let Some((choices, selected)) = self.build_manage_choices(true) {
                        self.mode = Mode::Kill {
                            choices,
                            selected,
                            first: 0,
                        };
                    }
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if !self.matches.is_empty() => {
                    step_selection(&mut self.attach_selected, self.matches.len(), false);
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if !self.matches.is_empty() => {
                    step_selection(&mut self.attach_selected, self.matches.len(), true);
                    None
                }
                _ => {
                    if self.attach_input.handle_key(code, modifiers) == EditOutcome::Changed {
                        self.recompute_matches();
                    }
                    None
                }
            },
            Mode::NewSession {
                server_index,
                input,
                ..
            } => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Enter, _) => Some(Outcome::Selected(Selection::Attach(
                    AttachSelection::NewSession {
                        server_index: *server_index,
                        label: input.trimmed_non_empty(),
                    },
                ))),
                (KeyCode::Char('t'), KeyModifiers::CONTROL) if !self.sessions.is_empty() => {
                    let chosen_server = *server_index;
                    let session_index = self
                        .sessions
                        .iter()
                        .position(|session| session.server_index == chosen_server)
                        .unwrap_or_else(|| self.default_session_index());
                    self.mode = Mode::NewWindow {
                        session_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if self.servers.len() > 1 => {
                    step_selection(server_index, self.servers.len(), false);
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if self.servers.len() > 1 => {
                    step_selection(server_index, self.servers.len(), true);
                    None
                }
                _ => {
                    input.handle_key(code, modifiers);
                    None
                }
            },
            Mode::NewWindow {
                session_index,
                input,
                ..
            } => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Enter, _) => Some(Outcome::Selected(Selection::Attach(
                    AttachSelection::NewWindow {
                        session_index: *session_index,
                        label: input.trimmed_non_empty(),
                    },
                ))),
                (KeyCode::Char('n'), KeyModifiers::CONTROL) if !self.servers.is_empty() => {
                    let server_index = self.sessions[*session_index].server_index;
                    self.mode = Mode::NewSession {
                        server_index,
                        first: 0,
                        input: TextInput::default(),
                    };
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if self.sessions.len() > 1 => {
                    step_selection(session_index, self.sessions.len(), false);
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if self.sessions.len() > 1 => {
                    step_selection(session_index, self.sessions.len(), true);
                    None
                }
                _ => {
                    input.handle_key(code, modifiers);
                    None
                }
            },
            Mode::Rename {
                choices,
                selected,
                input,
                dirty,
                ..
            } => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Enter, _) => {
                    if !*dirty {
                        self.mode = Mode::Attach;
                        return None;
                    }
                    let target = choices[*selected].target.clone();
                    let label = input.text().trim().to_owned();
                    Some(Outcome::Selected(Selection::Rename { target, label }))
                }
                (KeyCode::Up | KeyCode::BackTab, _) if choices.len() > 1 => {
                    step_selection(selected, choices.len(), false);
                    if !*dirty {
                        *input = TextInput::from_text(&choices[*selected].initial_label);
                    }
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if choices.len() > 1 => {
                    step_selection(selected, choices.len(), true);
                    if !*dirty {
                        *input = TextInput::from_text(&choices[*selected].initial_label);
                    }
                    None
                }
                _ => {
                    if input.handle_key(code, modifiers) == EditOutcome::Changed {
                        *dirty = true;
                    }
                    None
                }
            },
            Mode::Kill {
                choices, selected, ..
            } => match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Char('n' | 'N'), mods)
                    if mods.difference(KeyModifiers::SHIFT).is_empty() =>
                {
                    self.mode = Mode::Attach;
                    None
                }
                (KeyCode::Enter, _) => Some(Outcome::Selected(Selection::Kill {
                    target: choices[*selected].target.clone(),
                })),
                (KeyCode::Char('y' | 'Y'), mods)
                    if mods.difference(KeyModifiers::SHIFT).is_empty() =>
                {
                    Some(Outcome::Selected(Selection::Kill {
                        target: choices[*selected].target.clone(),
                    }))
                }
                (KeyCode::Char('s' | 'S'), mods)
                    if mods.difference(KeyModifiers::SHIFT).is_empty() =>
                {
                    let next = if matches!(choices[*selected].target.scope, ManageScope::Session) {
                        choices[*selected + 1..]
                            .iter()
                            .position(|c| matches!(c.target.scope, ManageScope::Session))
                            .map(|offset| *selected + 1 + offset)
                            .or_else(|| {
                                choices
                                    .iter()
                                    .position(|c| matches!(c.target.scope, ManageScope::Session))
                            })
                    } else {
                        choices
                            .iter()
                            .position(|c| matches!(c.target.scope, ManageScope::Session))
                    };
                    if let Some(pos) = next {
                        *selected = pos;
                    }
                    None
                }
                (KeyCode::Char('w' | 'W'), mods)
                    if mods.difference(KeyModifiers::SHIFT).is_empty() =>
                {
                    if let Some(pos) = choices
                        .iter()
                        .position(|c| matches!(c.target.scope, ManageScope::Window(_)))
                    {
                        *selected = pos;
                    }
                    None
                }
                (KeyCode::Char('b' | 'B'), mods)
                    if mods.difference(KeyModifiers::SHIFT).is_empty() =>
                {
                    if let Some(pos) = choices
                        .iter()
                        .position(|c| matches!(c.target.scope, ManageScope::Block(_)))
                    {
                        *selected = pos;
                    }
                    None
                }
                (KeyCode::Up | KeyCode::BackTab, _) if choices.len() > 1 => {
                    step_selection(selected, choices.len(), false);
                    None
                }
                (KeyCode::Down | KeyCode::Tab, _) if choices.len() > 1 => {
                    step_selection(selected, choices.len(), true);
                    None
                }
                _ => None,
            },
        }
    }

    fn loading_message(&self) -> Option<String> {
        if !self.loading.is_empty() {
            Some(format_loading(&self.loading, self.loading_is_refresh))
        } else if self.refreshing {
            Some("Refreshing…".to_owned())
        } else {
            None
        }
    }

    fn render(
        &mut self,
        out: &mut impl Write,
        columns: u16,
        rows: u16,
        use_color: bool,
    ) -> io::Result<()> {
        let loading_in_body = matches!(self.mode, Mode::Attach)
            && self.targets.is_empty()
            && self.servers.is_empty()
            && self.loading_message().is_some();
        let banner = self.feedback.clone().or_else(|| {
            if let Some(warn) = format_warnings_summary(&self.discovery_warnings) {
                let text = if !loading_in_body && let Some(loading) = self.loading_message() {
                    format!("{warn} · {loading}")
                } else {
                    warn
                };
                Some(Feedback {
                    text,
                    is_error: true,
                })
            } else if !loading_in_body {
                self.loading_message().map(|text| Feedback {
                    text,
                    is_error: false,
                })
            } else {
                None
            }
        });
        self.render_with_banner(out, columns, rows, use_color, banner.as_ref())
    }

    fn render_with_banner(
        &mut self,
        out: &mut impl Write,
        columns: u16,
        rows: u16,
        use_color: bool,
        banner: Option<&Feedback>,
    ) -> io::Result<()> {
        let width = usize::from(columns.saturating_sub(1));
        let show_banner = banner.is_some() && rows > 2 && width > 2;
        let list_rows = if show_banner {
            usize::from(rows.saturating_sub(2)).max(1)
        } else {
            usize::from(rows.saturating_sub(1)).max(1)
        };
        queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;

        let (prompt, displayed, offset, prompt_color) = match &mut self.mode {
            Mode::Attach => {
                self.attach_first =
                    scroll_first(self.attach_first, self.attach_selected, list_rows);
                if rows > 1 && width > 2 {
                    if self.targets.is_empty() {
                        let loading_hint;
                        let hint: &str = if self.servers.is_empty() {
                            if !self.loading.is_empty() {
                                loading_hint =
                                    format_loading(&self.loading, self.loading_is_refresh);
                                &loading_hint
                            } else if self.refreshing {
                                "Refreshing…"
                            } else {
                                "No reachable servers — press Esc to quit"
                            }
                        } else if self.sessions.is_empty() {
                            "No sessions yet — press Ctrl-N to create one"
                        } else {
                            "No open windows — Ctrl-T new window, Ctrl-N new session, Ctrl-R rename, Ctrl-K kill"
                        };
                        queue!(out, MoveTo(0, 1))?;
                        render_hint(out, hint, width - 2)?;
                    } else if self.view == AttachView::Agents && !self.has_agents() {
                        let hint = "No active agents — press Ctrl-G or Esc to show all panes";
                        queue!(out, MoveTo(0, 1))?;
                        render_hint(out, hint, width - 2)?;
                    } else {
                        for (line, &(index, ref indices)) in self
                            .matches
                            .iter()
                            .skip(self.attach_first)
                            .take(list_rows)
                            .enumerate()
                        {
                            let active = self.attach_first + line == self.attach_selected;
                            queue!(out, MoveTo(0, (line + 1) as u16))?;
                            let spans = self.targets[index].styled_row(width - 2);
                            render_row(out, &spans, indices, active, use_color)?;
                        }
                    }
                }
                let (prompt, prompt_color) = match self.view {
                    AttachView::All => {
                        let prompt = if self.servers.is_empty() {
                            choose_prompt(width, &["Attach (Esc)> ", "Attach> "])
                        } else if self.sessions.is_empty() {
                            choose_prompt(
                                width,
                                &[
                                    "Attach (Ctrl-N new session, Esc)> ",
                                    "Attach (^N/Esc)> ",
                                    "Attach> ",
                                ],
                            )
                        } else {
                            choose_prompt(
                                width,
                                &[
                                    "Attach (Ctrl-G agents, Ctrl-N session, Ctrl-T window, Ctrl-R rename, Ctrl-K kill, Esc)> ",
                                    "Attach (^G agents, ^N session, ^T window, ^R rename, ^K kill, Esc)> ",
                                    "Attach (^G/^N/^T/^R/^K/Esc)> ",
                                    "Attach> ",
                                ],
                            )
                        };
                        (prompt, Color::DarkCyan)
                    }
                    AttachView::Agents => {
                        let prompt = if self.servers.is_empty() {
                            choose_prompt(width, &["Agents (Ctrl-G all, Esc: back)> ", "Agents> "])
                        } else if self.sessions.is_empty() {
                            choose_prompt(
                                width,
                                &[
                                    "Agents (Ctrl-G all, Ctrl-N new session, Esc: back)> ",
                                    "Agents (^G all, ^N/Esc)> ",
                                    "Agents> ",
                                ],
                            )
                        } else {
                            choose_prompt(
                                width,
                                &[
                                    "Agents (Ctrl-G all, Ctrl-N session, Ctrl-T window, Ctrl-R rename, Ctrl-K kill, Esc: back)> ",
                                    "Agents (^G all, ^N session, ^T window, ^R rename, ^K kill, Esc)> ",
                                    "Agents (^G/^N/^T/^R/^K/Esc)> ",
                                    "Agents> ",
                                ],
                            )
                        };
                        (prompt, Color::DarkMagenta)
                    }
                };
                let (displayed, offset) = self
                    .attach_input
                    .visible(width.saturating_sub(prompt.width()));
                (prompt.to_owned(), displayed, offset, prompt_color)
            }
            Mode::NewSession {
                server_index,
                first,
                input,
            } => {
                let server_label = format!("[{}]", self.servers[*server_index]);
                render_create_mode(
                    out,
                    &self.servers,
                    *server_index,
                    first,
                    input,
                    CreatePromptCopy {
                        noun: "session",
                        prep: "on",
                        container_noun: "server",
                        container_display: &server_label,
                    },
                    rows,
                    width,
                    list_rows,
                    use_color,
                    |server, cols| styled_server_row(server, cols),
                )?
            }
            Mode::NewWindow {
                session_index,
                first,
                input,
            } => {
                let session_label = self.sessions[*session_index].display_name();
                render_create_mode(
                    out,
                    &self.sessions,
                    *session_index,
                    first,
                    input,
                    CreatePromptCopy {
                        noun: "window",
                        prep: "in",
                        container_noun: "session",
                        container_display: &session_label,
                    },
                    rows,
                    width,
                    list_rows,
                    use_color,
                    |session, cols| session.styled_row(cols),
                )?
            }
            Mode::Rename {
                choices,
                selected,
                first,
                input,
                ..
            } => {
                *first = scroll_first(*first, *selected, list_rows);
                if rows > 1 && width > 2 {
                    let rendered = render_manage_choices(
                        out,
                        choices,
                        *first,
                        *selected,
                        list_rows,
                        width - 2,
                        use_color,
                    )?;
                    if rendered < list_rows {
                        queue!(out, MoveTo(0, (rendered + 1) as u16))?;
                        render_hint(
                            out,
                            "Type a new name, or clear with Ctrl-U to restore the server default",
                            width - 2,
                        )?;
                    }
                }
                let kind = choices[*selected].target.kind_name();
                let prompt = if choices.len() > 1 {
                    let full = format!("Rename {kind} (Tab: target, Ctrl-U: reset, Esc: back)> ");
                    let medium = format!("Rename {kind} (Tab: target, Esc: back)> ");
                    let short = format!("Rename {kind} (Tab)> ");
                    let minimal = format!("Rename {kind}> ");
                    choose_prompt(width, &[&full, &medium, &short, &minimal, "Rename> "]).to_owned()
                } else {
                    let full = format!("Rename {kind} (Ctrl-U: reset, Esc: back)> ");
                    let medium = format!("Rename {kind} (Esc: back)> ");
                    let minimal = format!("Rename {kind}> ");
                    choose_prompt(width, &[&full, &medium, &minimal, "Rename> "]).to_owned()
                };
                let (displayed, offset) = input.visible(width.saturating_sub(prompt.width()));
                (prompt, displayed, offset, Color::DarkCyan)
            }
            Mode::Kill {
                choices,
                selected,
                first,
            } => {
                *first = scroll_first(*first, *selected, list_rows);
                if rows > 1 && width > 2 {
                    let _ = render_manage_choices(
                        out,
                        choices,
                        *first,
                        *selected,
                        list_rows,
                        width - 2,
                        use_color,
                    )?;
                }
                let kind = choices[*selected].target.kind_name();
                let prompt = if choices.len() > 1 {
                    let full =
                        format!("Kill {kind}? (Enter/y: kill, Tab/s/w/b: target, Esc: back) ");
                    let medium = format!("Kill {kind}? (Enter/y: kill, Tab: target, Esc: back) ");
                    let short = format!("Kill {kind}? (y/n, Tab) ");
                    let minimal = format!("Kill {kind}? (y/n) ");
                    choose_prompt_with_tail(width, 0, &[&full, &medium, &short, &minimal, "Kill? "])
                        .to_owned()
                } else {
                    let full = format!("Kill {kind}? (Enter/y: kill, Esc: back) ");
                    let minimal = format!("Kill {kind}? (y/n) ");
                    choose_prompt_with_tail(width, 0, &[&full, &minimal, "Kill? "]).to_owned()
                };
                (prompt, String::new(), 0, Color::DarkRed)
            }
        };

        if show_banner && let Some(banner) = banner {
            queue!(out, MoveTo(0, rows - 1))?;
            render_banner(out, banner, width - 2, use_color)?;
        }

        queue!(out, MoveTo(0, 0))?;
        render_prompt(out, &prompt, &displayed, prompt_color, use_color)?;
        queue!(out, MoveTo((prompt.width() + offset) as u16, 0))?;
        out.flush()
    }
}

struct CreatePromptCopy<'a> {
    noun: &'a str,
    prep: &'a str,
    container_noun: &'a str,
    container_display: &'a str,
}

#[allow(clippy::too_many_arguments)]
fn render_create_mode<T>(
    out: &mut impl Write,
    items: &[T],
    selected: usize,
    first: &mut usize,
    input: &TextInput,
    copy: CreatePromptCopy<'_>,
    rows: u16,
    width: usize,
    list_rows: usize,
    use_color: bool,
    style_item: impl Fn(&T, usize) -> Vec<StyledSpan>,
) -> io::Result<(String, String, usize, Color)> {
    *first = scroll_first(*first, selected, list_rows);
    if rows > 1 && width > 2 {
        if items.len() > 1 {
            for (line, item) in items.iter().skip(*first).take(list_rows).enumerate() {
                let active = *first + line == selected;
                queue!(out, MoveTo(0, (line + 1) as u16))?;
                let spans = style_item(item, width - 2);
                render_row(out, &spans, &[], active, use_color)?;
            }
        } else {
            queue!(out, MoveTo(0, 1))?;
            render_hint(
                out,
                &format!(
                    "Type a {} name, or press Enter for a default name",
                    copy.noun
                ),
                width - 2,
            )?;
        }
    }
    let noun = copy.noun;
    let prep = copy.prep;
    let container = copy.container_display;
    let fallback = format!("New {noun}> ");
    let prompt = if items.len() > 1 {
        let full = format!(
            "New {noun} name {prep} {container} (Tab: {}, Esc: back)> ",
            copy.container_noun
        );
        let medium = format!("New {noun} {prep} {container} (Tab)> ");
        let short = format!("New {noun} {prep} {container}> ");
        choose_prompt(width, &[&full, &medium, &short, &fallback]).to_owned()
    } else {
        let full = format!("New {noun} name {prep} {container} (Enter: default, Esc: back)> ");
        let medium = format!("New {noun} name {prep} {container}> ");
        let short = format!("New {noun} name> ");
        choose_prompt(width, &[&full, &medium, &short, &fallback]).to_owned()
    };
    let (displayed, offset) = input.visible(width.saturating_sub(prompt.width()));
    Ok((prompt, displayed, offset, Color::DarkCyan))
}

fn render_manage_choices(
    out: &mut impl Write,
    choices: &[ManageChoice],
    first: usize,
    selected: usize,
    list_rows: usize,
    max_width: usize,
    use_color: bool,
) -> io::Result<usize> {
    let mut rendered = 0;
    for (line, choice) in choices.iter().skip(first).take(list_rows).enumerate() {
        let active = first + line == selected;
        queue!(out, MoveTo(0, (line + 1) as u16))?;
        let tag = format!("{:<SCOPE_COLUMN_WIDTH$}", choice.target.scope.label());
        let spans = styled_scope_row(&tag, &choice.display, &choice.detail, max_width);
        render_row(out, &spans, &[], active, use_color)?;
        rendered += 1;
    }
    Ok(rendered)
}

fn step_selection(selected: &mut usize, len: usize, forward: bool) {
    if forward {
        *selected = (*selected + 1) % len;
    } else {
        *selected = (*selected + len - 1) % len;
    }
}

fn format_loading(servers: &[String], is_refresh: bool) -> String {
    let prefix = if is_refresh {
        "Refreshing"
    } else {
        "Connecting to"
    };
    match servers {
        [] => format!("{prefix}…"),
        [one] => format!("{prefix} {one}…"),
        [first, second] => format!("{prefix} {first}, {second}…"),
        [first, second, rest @ ..] => {
            format!("{prefix} {first}, {second}, +{} more…", rest.len())
        }
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

fn scroll_first(first: usize, selected: usize, visible: usize) -> usize {
    first
        .min(selected)
        .max((selected + 1).saturating_sub(visible))
}

fn choose_prompt<'a>(width: usize, candidates: &[&'a str]) -> &'a str {
    choose_prompt_with_tail(width, MIN_INPUT_WIDTH, candidates)
}

fn choose_prompt_with_tail<'a>(width: usize, min_tail: usize, candidates: &[&'a str]) -> &'a str {
    for candidate in candidates {
        if width >= candidate.width() + min_tail {
            return candidate;
        }
    }
    if width > 2 { "> " } else { "" }
}

fn is_quit_key(code: KeyCode, modifiers: KeyModifiers, detach_key: DetachKey) -> bool {
    if !modifiers.contains(KeyModifiers::CONTROL)
        || modifiers.contains(KeyModifiers::ALT)
        || modifiers.contains(KeyModifiers::SUPER)
    {
        return false;
    }
    if matches!(code, KeyCode::Char('c' | 'C')) && !modifiers.contains(KeyModifiers::SHIFT) {
        return true;
    }
    let Some(ctrl_byte) = detach_key.ctrl_byte() else {
        return false;
    };
    let shift = modifiers.contains(KeyModifiers::SHIFT);
    // In raw Unix mode crossterm decodes ASCII 0x1c..=0x1f as Ctrl-4..Ctrl-7,
    // while Kitty / modifyOtherKeys sends the punctuation key directly.
    match ctrl_byte {
        0x00 => matches!(code, KeyCode::Char('@' | ' ' | '2')),
        0x01..=0x1a => {
            !shift
                && matches!(
                    code,
                    KeyCode::Char(ch) if ch.to_ascii_lowercase() as u8 == b'a' + ctrl_byte - 1
                )
        }
        0x1c => !shift && matches!(code, KeyCode::Char('\\' | '4')),
        0x1d => !shift && matches!(code, KeyCode::Char(']' | '5')),
        0x1e => matches!(code, KeyCode::Char('^' | '6')),
        0x1f => matches!(code, KeyCode::Char('_' | '7' | '/' | '-')),
        _ => false,
    }
}

/// Drains any input already queued in the terminal buffer (while raw mode is
/// active) and returns true if a quit key (`Ctrl-C` or the configured detach
/// key) was queued, enabling instant double-detach without re-entering the
/// alternate screen.
pub(super) fn take_queued_quit_key(detach_key: DetachKey) -> io::Result<bool> {
    while event::poll(Duration::ZERO)? {
        if let Event::Key(key) = event::read()?
            && key.kind != KeyEventKind::Release
            && is_quit_key(key.code, key.modifiers, detach_key)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Keeps raw mode continuously enabled across picker <-> attach transitions so
/// pressing `Ctrl-\` during detach never hits cooked-mode `SIGQUIT`.
pub(super) struct RawModeGuard;

impl RawModeGuard {
    pub(super) fn enter() -> io::Result<Self> {
        terminal::enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

pub(super) struct Screen {
    use_color: bool,
}

impl Screen {
    pub(super) fn enter(_raw: &RawModeGuard) -> io::Result<Self> {
        let screen = Self {
            use_color: color_enabled(),
        };
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(screen)
    }

    fn render(&self, out: &mut impl Write, state: &mut PickerState) -> io::Result<()> {
        let (columns, rows) = terminal::size()?;
        state.render(out, columns, rows, self.use_color)
    }

    pub(super) fn step(
        &mut self,
        state: &mut PickerState,
        has_pending_updates: bool,
    ) -> io::Result<StepEvent> {
        let mut out = io::stdout();
        self.render(&mut out, state)?;
        loop {
            let (dirty, step) = handle_event(state, event::read()?);
            if let Some(step) = step {
                return Ok(step);
            }
            if has_pending_updates && state.is_attach_mode() {
                return Ok(StepEvent::FlushPending);
            }
            if dirty {
                self.render(&mut out, state)?;
            }
        }
    }

    pub(super) async fn step_until(
        &mut self,
        state: &mut PickerState,
        stream: &mut super::DiscoveryStream<'_>,
        has_pending_updates: bool,
    ) -> io::Result<StepEvent> {
        let mut out = io::stdout();
        self.render(&mut out, state)?;

        let mut tick = tokio::time::interval(Duration::from_millis(16));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                event = stream.next() => {
                    return Ok(match event {
                        Some(update) => StepEvent::Discovery(update),
                        None => StepEvent::DiscoveryFinished,
                    });
                }
                _ = tick.tick() => {
                    let mut dirty = false;
                    while event::poll(Duration::ZERO)? {
                        let (event_dirty, step) = handle_event(state, event::read()?);
                        if let Some(step) = step {
                            return Ok(step);
                        }
                        if has_pending_updates && state.is_attach_mode() {
                            return Ok(StepEvent::FlushPending);
                        }
                        dirty |= event_dirty;
                    }
                    if dirty {
                        self.render(&mut out, state)?;
                    }
                }
            }
        }
    }

    pub(super) fn render_busy(&mut self, state: &mut PickerState, message: &str) -> io::Result<()> {
        let mut out = io::stdout();
        let (columns, rows) = terminal::size()?;
        let banner = Feedback {
            text: message.to_owned(),
            is_error: false,
        };
        state.render_with_banner(&mut out, columns, rows, self.use_color, Some(&banner))
    }

    pub(super) fn drain_input(&mut self) -> io::Result<()> {
        while event::poll(Duration::ZERO)? {
            let _ = event::read()?;
        }
        Ok(())
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            SetAttribute(Attribute::Reset),
            LeaveAlternateScreen
        );
    }
}

fn handle_event(state: &mut PickerState, ev: Event) -> (bool, Option<StepEvent>) {
    match ev {
        Event::Resize(_, _) => (true, None),
        Event::Key(key) if key.kind != KeyEventKind::Release => {
            let step = state
                .handle_key(key.code, key.modifiers)
                .map(StepEvent::from);
            (true, step)
        }
        _ => (false, None),
    }
}

fn color_enabled() -> bool {
    env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
}

fn render_prompt(
    out: &mut impl Write,
    prompt: &str,
    query: &str,
    color: Color,
    use_color: bool,
) -> io::Result<()> {
    if !prompt.is_empty() {
        if use_color {
            queue!(out, SetForegroundColor(color))?;
        }
        queue!(
            out,
            SetAttribute(Attribute::Bold),
            Print(prompt),
            SetAttribute(Attribute::Reset)
        )?;
    }
    queue!(out, Print(query))
}

fn render_banner(
    out: &mut impl Write,
    banner: &Feedback,
    max_width: usize,
    use_color: bool,
) -> io::Result<()> {
    let visible = truncate_with_ellipsis(&banner.text, max_width);
    queue!(out, Print("  "))?;
    if banner.is_error {
        if use_color {
            queue!(out, SetForegroundColor(Color::DarkRed))?;
        }
        queue!(out, SetAttribute(Attribute::Bold))?;
    } else if use_color {
        queue!(out, SetForegroundColor(Color::DarkGreen))?;
    } else {
        queue!(out, SetAttribute(Attribute::Dim))?;
    }
    queue!(out, Print(visible), SetAttribute(Attribute::Reset))
}

fn render_hint(out: &mut impl Write, text: &str, max_width: usize) -> io::Result<()> {
    let visible = truncate_with_ellipsis(text, max_width);
    queue!(
        out,
        Print("  "),
        SetAttribute(Attribute::Dim),
        Print(visible),
        SetAttribute(Attribute::Reset)
    )
}

fn render_row(
    out: &mut impl Write,
    spans: &[StyledSpan],
    match_indices: &[usize],
    active: bool,
    use_color: bool,
) -> io::Result<()> {
    if active {
        if use_color {
            queue!(out, SetForegroundColor(Color::DarkCyan))?;
        }
        queue!(
            out,
            SetAttribute(Attribute::Bold),
            Print("> "),
            SetAttribute(Attribute::Reset)
        )?;
    } else {
        queue!(out, Print("  "))?;
    }

    for span in spans {
        let mut run = String::new();
        let mut run_matched = None;
        for (char_index, ch) in span.text.chars().enumerate() {
            let matched = !match_indices.is_empty()
                && span
                    .search_offset
                    .is_some_and(|base| match_indices.binary_search(&(base + char_index)).is_ok());
            if run_matched == Some(matched) {
                run.push(ch);
            } else {
                if let Some(prev_matched) = run_matched {
                    render_run(out, &run, span.role, prev_matched, active, use_color)?;
                    run.clear();
                }
                run.push(ch);
                run_matched = Some(matched);
            }
        }
        if let Some(prev_matched) = run_matched {
            render_run(out, &run, span.role, prev_matched, active, use_color)?;
        }
    }
    queue!(out, SetAttribute(Attribute::Reset))
}

fn render_run(
    out: &mut impl Write,
    text: &str,
    role: StyleRole,
    matched: bool,
    active: bool,
    use_color: bool,
) -> io::Result<()> {
    queue!(out, SetAttribute(Attribute::Reset))?;
    if use_color && let Some(color) = foreground_color(role, matched) {
        queue!(out, SetForegroundColor(color))?;
    }
    if matched {
        queue!(
            out,
            SetAttribute(Attribute::Reverse),
            SetAttribute(Attribute::Bold)
        )?;
    } else if active {
        if matches!(
            role,
            StyleRole::Label | StyleRole::Status(ProgramState::Blocked | ProgramState::Error)
        ) {
            queue!(out, SetAttribute(Attribute::Bold))?;
        }
    } else {
        match role {
            StyleRole::Separator | StyleRole::Title | StyleRole::Status(ProgramState::Idle) => {
                queue!(out, SetAttribute(Attribute::Dim))?;
            }
            StyleRole::Status(ProgramState::Blocked | ProgramState::Error) => {
                queue!(out, SetAttribute(Attribute::Bold))?;
            }
            StyleRole::Server
            | StyleRole::Label
            | StyleRole::Status(ProgramState::Working | ProgramState::Done) => {}
        }
    }
    queue!(out, Print(text))
}

// Use the standard 8 ANSI palette colors (Dark*) so contrast adapts cleanly
// across both dark and light terminal themes.
fn foreground_color(role: StyleRole, matched: bool) -> Option<Color> {
    if matched {
        return Some(Color::DarkYellow);
    }
    match role {
        StyleRole::Server => Some(Color::DarkCyan),
        StyleRole::Label | StyleRole::Separator | StyleRole::Title => None,
        StyleRole::Status(ProgramState::Blocked) => Some(Color::DarkYellow),
        StyleRole::Status(ProgramState::Error) => Some(Color::DarkRed),
        StyleRole::Status(ProgramState::Working) => Some(Color::DarkCyan),
        StyleRole::Status(ProgramState::Done) => Some(Color::DarkGreen),
        StyleRole::Status(ProgramState::Idle) => None,
    }
}

fn word_left(query: &[char], cursor: usize) -> usize {
    cursor - word_distance(query[..cursor].iter().rev())
}

fn word_right(query: &[char], cursor: usize) -> usize {
    cursor + word_distance(query[cursor..].iter())
}

fn word_distance<'a>(chars: impl Iterator<Item = &'a char>) -> usize {
    let mut chars = chars.peekable();
    let mut distance = 0;
    while chars.next_if(|ch| !ch.is_alphanumeric()).is_some() {
        distance += 1;
    }
    while chars.next_if(|ch| ch.is_alphanumeric()).is_some() {
        distance += 1;
    }
    distance
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::picker::{test_target, test_target_full};

    fn chars(text: &str) -> Vec<char> {
        text.chars().collect()
    }

    fn type_text(state: &mut PickerState, text: &str) {
        for ch in text.chars() {
            assert_eq!(
                state.handle_key(KeyCode::Char(ch), KeyModifiers::NONE),
                None
            );
        }
    }

    fn sample_fixture() -> (Vec<Target>, Vec<SessionChoice>, Vec<String>) {
        let servers = vec!["local".to_owned(), "office".to_owned()];
        let sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
            SessionChoice {
                server_index: 1,
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                label: "api".to_owned(),
            },
        ];
        let targets = vec![
            test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:1"),
            test_target(1, 1, "[office] api / 1 nvim", "session:2", "block:2"),
        ];
        (targets, sessions, servers)
    }

    #[test]
    fn word_navigation_moves_across_delimiters_and_words() {
        let query = chars("  office / dev-1  ");
        assert_eq!(word_left(&query, 0), 0);
        assert_eq!(word_left(&query, query.len()), 15);
        assert_eq!(word_left(&query, 15), 11);
        assert_eq!(word_left(&query, 11), 2);
        assert_eq!(word_left(&query, 2), 0);

        assert_eq!(word_right(&query, 0), 8);
        assert_eq!(word_right(&query, 8), 14);
        assert_eq!(word_right(&query, 14), 16);
        assert_eq!(word_right(&query, 16), query.len());
        assert_eq!(word_right(&query, query.len()), query.len());
    }

    #[test]
    fn word_navigation_handles_empty_and_unicode_queries() {
        let empty = chars("");
        assert_eq!(word_left(&empty, 0), 0);
        assert_eq!(word_right(&empty, 0), 0);

        let unicode = chars("π-αβ");
        assert_eq!(word_right(&unicode, 0), 1);
        assert_eq!(word_right(&unicode, 1), 4);
        assert_eq!(word_left(&unicode, 4), 2);
        assert_eq!(word_left(&unicode, 2), 0);
    }

    #[test]
    fn render_row_applies_semantic_colors_match_highlights_and_no_color() {
        let spans = vec![
            StyledSpan {
                role: StyleRole::Server,
                text: "[local]".to_owned(),
                search_offset: Some(0),
            },
            StyledSpan {
                role: StyleRole::Label,
                text: " work".to_owned(),
                search_offset: Some(7),
            },
            StyledSpan {
                role: StyleRole::Separator,
                text: " · ".to_owned(),
                search_offset: Some(12),
            },
            StyledSpan {
                role: StyleRole::Status(ProgramState::Error),
                text: "error build".to_owned(),
                search_offset: Some(15),
            },
        ];

        let mut colored = Vec::new();
        render_row(&mut colored, &spans, &[8, 9], false, true).unwrap();
        let colored = String::from_utf8(colored).unwrap();
        // Server cyan (ANSI 6), matched "wo" reverse+bold+yellow (ANSI 3), error red (ANSI 1).
        assert!(colored.contains("\x1b[38;5;6m") || colored.contains("\x1b[36m"));
        assert!(colored.contains("\x1b[38;5;3m") || colored.contains("\x1b[33m"));
        assert!(colored.contains("\x1b[38;5;1m") || colored.contains("\x1b[31m"));
        assert!(colored.contains("\x1b[7m"));
        assert!(colored.contains("wo"));
        assert!(colored.contains("rk"));
        assert!(colored.ends_with("\x1b[0m"));

        let mut active_unmatched = Vec::new();
        render_row(&mut active_unmatched, &spans, &[], true, true).unwrap();
        let active_unmatched = String::from_utf8(active_unmatched).unwrap();
        // Active row without matches shows the "> " indicator without a row-wide background.
        assert!(active_unmatched.contains("> "));
        assert!(!active_unmatched.contains("\x1b[7m"));

        let mut active_plain = Vec::new();
        render_row(&mut active_plain, &spans, &[8, 9], true, false).unwrap();
        let active_plain = String::from_utf8(active_plain).unwrap();
        // NO_COLOR mode emits no foreground color escapes, but keeps reverse and bold on matches.
        assert!(!active_plain.contains("\x1b[38;"));
        assert!(!active_plain.contains("\x1b[31m"));
        assert!(!active_plain.contains("\x1b[33m"));
        assert!(!active_plain.contains("\x1b[36m"));
        assert!(active_plain.contains("\x1b[7m"));
        assert!(active_plain.contains("> "));
    }

    #[test]
    fn ctrl_n_creates_new_session_with_default_or_custom_label_and_server_choice() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        // Highlight [office] api, then press Ctrl-N: office (index 1) is pre-selected.
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        // Tab wraps to local (index 0); type a name with surrounding spaces.
        assert_eq!(state.handle_key(KeyCode::Tab, KeyModifiers::NONE), None);
        type_text(&mut state, "  scratch  ");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::NewSession {
                    server_index: 0,
                    label: Some("scratch".to_owned()),
                }
            )))
        );

        // Blank or whitespace-only name produces None (default Rex label).
        let mut state = PickerState::new(targets, sessions, servers);
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "   ");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::NewSession {
                    server_index: 1,
                    label: None,
                }
            )))
        );
    }

    #[test]
    fn ctrl_t_creates_new_window_in_highlighted_or_cycled_session() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        // Highlight [office] api, then press Ctrl-T: session 1 is pre-selected.
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "logs");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::NewWindow {
                    session_index: 1,
                    label: Some("logs".to_owned()),
                }
            )))
        );

        // Can cycle to another session and submit empty name for default label.
        let mut state = PickerState::new(targets, sessions, servers);
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::NewWindow {
                    session_index: 1,
                    label: None,
                }
            )))
        );
    }

    #[test]
    fn esc_returns_to_attach_preserving_query_and_ctrl_c_cancels_from_any_mode() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets, sessions, servers);

        type_text(&mut state, "api");
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "temp");
        // Esc backs out to Attach without cancelling the picker.
        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(1)
            )))
        );

        // Ctrl-C cancels immediately even inside NewWindow mode.
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Some(Outcome::Cancel)
        );
    }

    #[test]
    fn ctrl_backslash_cancels_from_every_picker_mode() {
        let (targets, sessions, servers) = split_fixture();
        // Both Kitty/modifyOtherKeys (Ctrl-\) and legacy 0x1c (crossterm Ctrl-4) must cancel.
        for detach_key in [KeyCode::Char('\\'), KeyCode::Char('4')] {
            for enter_mode in [
                None,
                Some(KeyCode::Char('g')),
                Some(KeyCode::Char('n')),
                Some(KeyCode::Char('t')),
                Some(KeyCode::Char('r')),
                Some(KeyCode::Char('k')),
            ] {
                let mut state =
                    PickerState::new(targets.clone(), sessions.clone(), servers.clone());
                if let Some(key) = enter_mode {
                    assert_eq!(state.handle_key(key, KeyModifiers::CONTROL), None);
                }
                assert_eq!(
                    state.handle_key(detach_key, KeyModifiers::CONTROL),
                    Some(Outcome::Cancel),
                    "expected {detach_key:?} to cancel in mode {enter_mode:?}"
                );
            }
        }
    }

    #[test]
    fn empty_server_allows_ctrl_n_and_ignores_ctrl_t() {
        let servers = vec!["local".to_owned()];
        let mut state = PickerState::new(Vec::new(), Vec::new(), servers);

        // Ctrl-T, Ctrl-R, Ctrl-K are ignored when there are no sessions.
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));

        // Render empty state cleanly.
        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("No sessions yet"));
        assert!(screen.contains("Ctrl-N"));

        // Ctrl-N creates a session on the sole reachable server.
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "dev");
        let mut new_buf = Vec::new();
        state.render(&mut new_buf, 80, 10, false).unwrap();
        let new_screen = String::from_utf8(new_buf).unwrap();
        assert!(new_screen.contains("New session name on [local]"));
        assert!(new_screen.contains("dev"));

        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::NewSession {
                    server_index: 0,
                    label: Some("dev".to_owned()),
                }
            )))
        );
    }

    #[test]
    fn switching_between_new_session_and_new_window_preserves_context() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets, sessions, servers);

        // Open NewSession on local (index 0), move to office (index 1), then press Ctrl-T.
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        // Should land on office's session (index 1).
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::NewWindow {
                    session_index: 1,
                    label: None,
                }
            )))
        );
    }

    #[test]
    fn renders_multi_server_and_multi_session_prompts_including_narrow_and_unicode() {
        let servers = vec!["local".to_owned(), "日本語サーバー".to_owned()];
        let sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
            SessionChoice {
                server_index: 1,
                server_name: "日本語サーバー".to_owned(),
                session_id: "session:2".to_owned(),
                label: "開発セッション".to_owned(),
            },
        ];
        let targets = vec![
            test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:1"),
            test_target(
                1,
                1,
                "[日本語サーバー] 開発セッション / 1 zsh",
                "session:2",
                "block:2",
            ),
        ];
        let mut state = PickerState::new(targets, sessions, servers);

        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::CONTROL),
            None
        );
        for (cols, rows) in [(100, 10), (40, 5), (10, 3), (3, 2), (1, 1)] {
            let mut buf = Vec::new();
            state.render(&mut buf, cols, rows, true).unwrap();
            let output = String::from_utf8(buf).unwrap();
            if cols >= 100 {
                assert!(output.contains("[local]"));
                assert!(output.contains("[日本語サーバー]"));
            }
        }

        assert_eq!(
            state.handle_key(KeyCode::Char('t'), KeyModifiers::CONTROL),
            None
        );
        for (cols, rows) in [(100, 10), (40, 5), (10, 3), (3, 2), (1, 1)] {
            let mut buf = Vec::new();
            state.render(&mut buf, cols, rows, false).unwrap();
            let output = String::from_utf8(buf).unwrap();
            if cols >= 100 {
                assert!(output.contains("[local]"));
                assert!(output.contains("開発セッション"));
            }
        }

        // Also render Rename and Kill modes across narrow and Unicode sizes.
        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        for (cols, rows) in [(100, 10), (40, 5), (10, 3), (3, 2), (1, 1)] {
            let mut buf = Vec::new();
            state.render(&mut buf, cols, rows, true).unwrap();
        }
        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );
        for (cols, rows) in [(100, 10), (40, 5), (10, 3), (3, 2), (1, 1)] {
            let mut buf = Vec::new();
            state.render(&mut buf, cols, rows, true).unwrap();
        }
    }

    fn split_fixture() -> (Vec<Target>, Vec<SessionChoice>, Vec<String>) {
        let servers = vec!["local".to_owned()];
        let sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:empty".to_owned(),
                label: "idle".to_owned(),
            },
        ];
        let targets = vec![
            test_target_full(
                0,
                0,
                "[local] work / 1 zsh",
                "session:1",
                "window:1",
                1,
                None,
                1,
                "block:1",
                1,
                None,
                "shell",
                Some("zsh"),
            ),
            test_target_full(
                0,
                0,
                "[local] work / 2.1 dev / editor / nvim",
                "session:1",
                "window:2",
                2,
                Some("dev"),
                2,
                "block:2",
                1,
                Some("editor"),
                "editor",
                Some("nvim"),
            ),
            test_target_full(
                0,
                0,
                "[local] work / 2.2 dev / zsh",
                "session:1",
                "window:2",
                2,
                Some("dev"),
                2,
                "block:3",
                2,
                None,
                "shell",
                Some("zsh"),
            ),
        ];
        (targets, sessions, servers)
    }

    #[test]
    fn ctrl_r_renames_session_window_or_block_with_prefill_and_reset() {
        let (targets, sessions, servers) = split_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        // Single-block window defaults to Window scope with empty pre-fill for default label.
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        // Pressing Enter untouched is a no-op and returns to Attach.
        assert_eq!(state.handle_key(KeyCode::Enter, KeyModifiers::NONE), None);
        assert!(matches!(state.mode, Mode::Attach));

        // Open Rename on split row 2.1 (custom window "dev", custom block "editor").
        // Split rows default to Block scope, pre-filled with "editor".
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        // Before editing, Up moves to Window ("dev") and updates the input pre-fill.
        assert_eq!(state.handle_key(KeyCode::Up, KeyModifiers::NONE), None);
        // Clear with Ctrl-U to restore default label, then press Enter.
        assert_eq!(
            state.handle_key(KeyCode::Char('u'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Rename {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Window("window:2".to_owned()),
                },
                label: String::new(),
            }))
        );

        // Editing sets dirty so switching scope preserves the typed text.
        let mut state = PickerState::new(targets, sessions, servers);
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('u'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "  backend  ");
        // Move to Session (index 0: Block 2 -> Up -> Window 1 -> Up -> Session 0).
        assert_eq!(state.handle_key(KeyCode::Up, KeyModifiers::NONE), None);
        assert_eq!(state.handle_key(KeyCode::Up, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Rename {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
                },
                label: "backend".to_owned(),
            }))
        );
    }

    #[test]
    fn ctrl_k_kills_session_window_or_block_with_confirmation_and_shortcuts() {
        let (targets, sessions, servers) = split_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        // Highlight split row 2.1, open Kill: defaults to Block.
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );

        let mut buf = Vec::new();
        state.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("Kill block?"));
        assert!(screen.contains("(2 windows, 3 blocks)"));
        assert!(screen.contains("(2 blocks)"));
        assert!(screen.contains("(no windows)"));

        // 'n' backs out to Attach without killing.
        assert_eq!(
            state.handle_key(KeyCode::Char('n'), KeyModifiers::NONE),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));

        // Re-open Kill on split row 2.1: confirm default Block with 'y'.
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('y'), KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Kill {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Block("block:2".to_owned()),
                },
            }))
        );

        // 'w' selects Window, 's' selects Session, 'b' selects Block.
        let mut state = PickerState::new(targets, sessions, servers);
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('w'), KeyModifiers::NONE),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Kill {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Window("window:2".to_owned()),
                },
            }))
        );

        assert_eq!(
            state.handle_key(KeyCode::Char('s'), KeyModifiers::NONE),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Kill {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
                },
            }))
        );
    }

    #[test]
    fn empty_windows_still_allow_renaming_and_killing_sessions() {
        let servers = vec!["local".to_owned()];
        let sessions = vec![SessionChoice {
            server_index: 0,
            server_name: "local".to_owned(),
            session_id: "session:1".to_owned(),
            label: "empty-work".to_owned(),
        }];
        let mut state = PickerState::new(Vec::new(), sessions, servers);

        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('u'), KeyModifiers::CONTROL),
            None
        );
        type_text(&mut state, "fresh");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Rename {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
                },
                label: "fresh".to_owned(),
            }))
        );

        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Kill {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
                },
            }))
        );
    }

    #[test]
    fn refresh_preserves_query_selection_and_clears_feedback_on_next_key() {
        let (targets, sessions, servers) = split_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers);
        type_text(&mut state, "dev");
        assert_eq!(state.matches.len(), 2);
        // Select second match (block:3).
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);

        // Simulate renaming block:3 and refreshing (overwriting any prior banner).
        state.set_feedback(Feedback {
            text: "Old warning".to_owned(),
            is_error: true,
        });
        let mut updated = targets;
        updated[2].block_label = Some("logs".to_owned());
        state.refresh(
            updated,
            sessions,
            Feedback {
                text: "Renamed block to logs".to_owned(),
                is_error: false,
            },
        );
        assert_eq!(state.attach_input.text(), "dev");
        assert_eq!(
            state.feedback,
            Some(Feedback {
                text: "Renamed block to logs".to_owned(),
                is_error: false,
            })
        );
        // Previously selected block:3 stays selected after refresh.
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(2)
            )))
        );
        // Feedback cleared after keypress.
        assert!(state.feedback.is_none());
    }

    #[test]
    fn ctrl_k_s_cycles_through_all_sessions_including_empty_ones() {
        let (targets, sessions, servers) = split_fixture();
        let mut state = PickerState::new(targets, sessions, servers);

        // Highlight split row 2.1 (Block selected by default in Kill mode).
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );

        // First 's' jumps to the active session ("work").
        assert_eq!(
            state.handle_key(KeyCode::Char('s'), KeyModifiers::NONE),
            None
        );
        // Second 's' advances to the empty session ("idle").
        assert_eq!(
            state.handle_key(KeyCode::Char('s'), KeyModifiers::NONE),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Kill {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:empty".to_owned(),
                    scope: ManageScope::Session,
                },
            }))
        );

        // 'S' wraps back around to the first session ("work").
        assert_eq!(
            state.handle_key(KeyCode::Char('S'), KeyModifiers::SHIFT),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Kill {
                target: ManageTarget {
                    server_index: 0,
                    session_id: "session:1".to_owned(),
                    scope: ManageScope::Session,
                },
            }))
        );
    }

    #[test]
    fn initial_feedback_renders_in_banner_until_next_key() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets, sessions, servers);
        state.set_feedback(Feedback {
            text: "office: connection refused".to_owned(),
            is_error: true,
        });

        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("office: connection refused"));

        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert!(state.feedback.is_none());

        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(!screen.contains("office: connection refused"));
    }

    #[test]
    fn reset_after_attach_clears_query_and_focuses_detached_or_newly_created_block() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        // User filtered before attaching.
        type_text(&mut state, "api");
        assert_eq!(state.matches.len(), 1);

        // Detaching from [office] api clears the filter, focuses [office] api immediately,
        // and renders a refreshing banner until discovery finishes.
        state.reset_after_attach(
            Some(FocusTarget {
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                block_id: "block:2".to_owned(),
            }),
            None,
        );
        assert_eq!(state.attach_input.text(), "");
        assert_eq!(state.matches.len(), 2);
        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("Refreshing…"));

        // When discovery finishes with a new server order (office moved to index 0),
        // the detached block stays highlighted and the refreshing banner clears.
        let reordered_servers = vec!["office".to_owned(), "local".to_owned()];
        let reordered_sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                label: "api".to_owned(),
            },
            SessionChoice {
                server_index: 1,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
        ];
        let reordered_targets = vec![
            test_target(0, 0, "[office] api / 1 nvim", "session:2", "block:2"),
            test_target(1, 1, "[local] work / 1 zsh", "session:1", "block:1"),
        ];
        state.apply_discovery(
            reordered_targets,
            reordered_sessions,
            reordered_servers,
            None,
        );
        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(!screen.contains("Refreshing…"));
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(0)
            )))
        );

        // Detaching from a brand-new session that was not yet in the pre-attach list
        // focuses it as soon as discovery brings it in.
        state.reset_after_attach(
            Some(FocusTarget {
                server_name: "local".to_owned(),
                session_id: "session:new".to_owned(),
                block_id: "block:new".to_owned(),
            }),
            None,
        );
        let mut new_sessions = sessions;
        new_sessions.push(SessionChoice {
            server_index: 0,
            server_name: "local".to_owned(),
            session_id: "session:new".to_owned(),
            label: "scratch".to_owned(),
        });
        let mut new_targets = targets;
        new_targets.push(test_target(
            0,
            2,
            "[local] scratch / 1 zsh",
            "session:new",
            "block:new",
        ));
        state.apply_discovery(new_targets, new_sessions, servers, None);
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(2)
            )))
        );
    }

    #[test]
    fn user_navigation_during_refresh_overrides_pending_detach_focus() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        state.reset_after_attach(
            Some(FocusTarget {
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                block_id: "block:2".to_owned(),
            }),
            None,
        );
        // User moves up to [local] work before refresh completes.
        assert_eq!(state.handle_key(KeyCode::Up, KeyModifiers::NONE), None);

        state.apply_discovery(targets, sessions, servers, None);
        // Selection stays on [local] work (index 0) instead of snapping back to [office] api.
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(0)
            )))
        );
    }

    #[test]
    fn explicit_post_attach_feedback_takes_precedence_over_refreshing_banner() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        state.reset_after_attach(
            None,
            Some(Feedback {
                text: "The block closed".to_owned(),
                is_error: false,
            }),
        );
        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("The block closed"));
        assert!(!screen.contains("Refreshing…"));

        // Completing discovery preserves the explicit message until the next key.
        state.apply_discovery(targets, sessions, servers, None);
        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("The block closed"));
    }

    fn agents_fixture() -> (Vec<Target>, Vec<SessionChoice>, Vec<String>) {
        let servers = vec!["local".to_owned(), "office".to_owned()];
        let sessions = vec![
            SessionChoice {
                server_index: 0,
                server_name: "local".to_owned(),
                session_id: "session:1".to_owned(),
                label: "work".to_owned(),
            },
            SessionChoice {
                server_index: 1,
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                label: "api".to_owned(),
            },
        ];
        let targets = vec![
            // 0: plain shell (not an agent)
            test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:zsh"),
            // 1: agent process with no OSC 7501 status
            test_target(0, 0, "[local] work / 2 agy", "session:1", "block:agy")
                .with_agent_process(true),
            // 2: idle agent
            test_target(0, 0, "[local] work / 3 claude", "session:1", "block:idle")
                .with_status(ProgramState::Idle, "idle claude"),
            // 3: done agent
            test_target(1, 1, "[office] api / 1 codex", "session:2", "block:done")
                .with_status(ProgramState::Done, "done codex"),
            // 4: working agent (first)
            test_target(1, 1, "[office] api / 2 claude", "session:2", "block:work1")
                .with_status(ProgramState::Working, "working claude"),
            // 5: error agent
            test_target(0, 0, "[local] work / 4 opencode", "session:1", "block:err")
                .with_status(ProgramState::Error, "error opencode"),
            // 6: blocked agent
            test_target(1, 1, "[office] api / 3 claude", "session:2", "block:blk")
                .with_status(ProgramState::Blocked, "blocked claude (permission)"),
            // 7: working agent (second, preserves discovery order after index 4)
            test_target(0, 0, "[local] work / 5 gemini", "session:1", "block:work2")
                .with_status(ProgramState::Working, "working gemini"),
        ];
        (targets, sessions, servers)
    }

    #[test]
    fn ctrl_g_filters_to_agents_sorted_by_status_priority_and_preserves_ctrl_a() {
        let (targets, sessions, servers) = agents_fixture();
        let mut state = PickerState::new(targets, sessions, servers);

        assert_eq!(state.matches.len(), 8);
        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.view, AttachView::Agents);

        // Excludes plain zsh (0); sorts blocked(6), error(5), working(4, 7), done(3), idle(2), none(1).
        let ordered: Vec<usize> = state.matches.iter().map(|&(idx, _)| idx).collect();
        assert_eq!(ordered, vec![6, 5, 4, 7, 3, 2, 1]);

        // Agents prompt renders distinctly.
        let mut buf = Vec::new();
        state.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("Agents ("));

        // Ctrl-A still moves cursor to start of query instead of toggling Agents.
        type_text(&mut state, "claude");
        assert_eq!(
            state.handle_key(KeyCode::Char('a'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.view, AttachView::Agents);
        assert_eq!(state.attach_input.cursor, 0);
        // Typing at cursor 0 prepends to query.
        type_text(&mut state, "api ");
        assert_eq!(state.attach_input.text(), "api claude");
    }

    #[test]
    fn toggling_between_all_and_agents_preserves_highlighted_agent_and_esc_backs_out() {
        let (targets, sessions, servers) = agents_fixture();
        let mut state = PickerState::new(targets, sessions, servers);

        // Toggle into Agents: blocked agent (index 6) is selected.
        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        // Move down to error agent (index 5).
        assert_eq!(state.handle_key(KeyCode::Down, KeyModifiers::NONE), None);
        assert_eq!(state.matches[state.attach_selected].0, 5);

        // Esc from Agents returns to All view and keeps index 5 selected.
        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(state.view, AttachView::All);
        assert_eq!(state.matches[state.attach_selected].0, 5);

        // Ctrl-G from All while highlighting an agent keeps it selected in Agents.
        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.view, AttachView::Agents);
        assert_eq!(state.matches[state.attach_selected].0, 5);

        // Ctrl-G back to All, then Esc from All cancels the picker.
        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.view, AttachView::All);
        assert_eq!(
            state.handle_key(KeyCode::Esc, KeyModifiers::NONE),
            Some(Outcome::Cancel)
        );
    }

    #[test]
    fn attach_and_detach_from_agents_view_returns_to_agents_view_and_refocuses() {
        let (targets, sessions, servers) = agents_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers.clone());

        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        // Filter and attach to the blocked agent (index 6).
        type_text(&mut state, "blocked");
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(6)
            )))
        );

        // Detach returns to Agents view, clears query, and highlights block:blk.
        state.reset_after_attach(
            Some(FocusTarget {
                server_name: "office".to_owned(),
                session_id: "session:2".to_owned(),
                block_id: "block:blk".to_owned(),
            }),
            None,
        );
        assert_eq!(state.view, AttachView::Agents);
        assert_eq!(state.attach_input.text(), "");
        assert_eq!(state.matches[state.attach_selected].0, 6);

        // Background refresh updates block:blk from blocked -> working; it stays in Agents view
        // and stays highlighted even though its sorted rank moved behind error (index 5).
        let mut refreshed_targets = targets;
        refreshed_targets[6] = refreshed_targets[6]
            .clone()
            .with_status(ProgramState::Working, "working claude");
        state.apply_discovery(refreshed_targets, sessions, servers, None);
        assert_eq!(state.view, AttachView::Agents);
        let ordered: Vec<usize> = state.matches.iter().map(|&(idx, _)| idx).collect();
        assert_eq!(ordered, vec![5, 4, 6, 7, 3, 2, 1]);
        assert_eq!(state.matches[state.attach_selected].0, 6);
    }

    #[test]
    fn agents_view_handles_no_active_agents_and_manage_roundtrips() {
        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets, sessions, servers);

        // Switch to Agents when no targets are agents.
        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.view, AttachView::Agents);
        assert!(state.matches.is_empty());
        // Enter, Ctrl-R, Ctrl-K are no-ops when no agent row is available.
        assert_eq!(state.handle_key(KeyCode::Enter, KeyModifiers::NONE), None);
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));
        assert_eq!(
            state.handle_key(KeyCode::Char('k'), KeyModifiers::CONTROL),
            None
        );
        assert!(matches!(state.mode, Mode::Attach));

        let mut buf = Vec::new();
        state.render(&mut buf, 80, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("No active agents"));
        assert!(screen.contains("Agents"));

        // Manage (rename) from Agents view returns to Agents view after Esc and refresh.
        let (targets, sessions, servers) = agents_fixture();
        let mut state = PickerState::new(targets.clone(), sessions.clone(), servers);
        assert_eq!(
            state.handle_key(KeyCode::Char('g'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char('r'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(state.handle_key(KeyCode::Esc, KeyModifiers::NONE), None);
        assert_eq!(state.view, AttachView::Agents);
        assert!(matches!(state.mode, Mode::Attach));

        state.refresh(
            targets,
            sessions,
            Feedback {
                text: "Renamed window".to_owned(),
                is_error: false,
            },
        );
        assert_eq!(state.view, AttachView::Agents);
    }

    #[test]
    fn picker_quit_key_respects_configured_detach_key() {
        assert!(is_quit_key(
            KeyCode::Char('\\'),
            KeyModifiers::CONTROL,
            DetachKey::default()
        ));
        assert!(is_quit_key(
            KeyCode::Char('4'),
            KeyModifiers::CONTROL,
            DetachKey::default()
        ));
        assert!(!is_quit_key(
            KeyCode::Char('\\'),
            KeyModifiers::CONTROL | KeyModifiers::ALT,
            DetachKey::default()
        ));
        assert!(is_quit_key(
            KeyCode::Char(']'),
            KeyModifiers::CONTROL,
            DetachKey::Ctrl(0x1d)
        ));
        assert!(is_quit_key(
            KeyCode::Char('5'),
            KeyModifiers::CONTROL,
            DetachKey::Ctrl(0x1d)
        ));
        assert!(!is_quit_key(
            KeyCode::Char('\\'),
            KeyModifiers::CONTROL,
            DetachKey::Ctrl(0x1d)
        ));
        assert!(!is_quit_key(
            KeyCode::Char('\\'),
            KeyModifiers::CONTROL,
            DetachKey::None
        ));
        assert!(is_quit_key(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            DetachKey::None
        ));

        let (targets, sessions, servers) = sample_fixture();
        let mut state = PickerState::new(targets, sessions, servers);
        state.set_detach_key(DetachKey::Ctrl(0x1d));
        assert_eq!(
            state.handle_key(KeyCode::Char('\\'), KeyModifiers::CONTROL),
            None
        );
        assert_eq!(
            state.handle_key(KeyCode::Char(']'), KeyModifiers::CONTROL),
            Some(Outcome::Cancel)
        );
    }

    #[test]
    fn progressive_loading_renders_connecting_updates_and_timeout_warnings_and_preserves_focus() {
        // 1. Instant startup with empty list shows "Connecting to ..." instead of "No sessions yet".
        let mut state = PickerState::new(Vec::new(), Vec::new(), Vec::new());
        state.set_loading(
            vec!["local".to_owned(), "office".to_owned(), "lab".to_owned()],
            false,
        );
        let mut buf = Vec::new();
        state.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("Connecting to local, office, +1 more…"));
        assert!(!screen.contains("No sessions yet"));

        // 2. Fast local server connects: its target appears immediately while remote servers still load.
        let local_target = test_target(0, 0, "[local] work / 1 zsh", "session:1", "block:1");
        let local_session = SessionChoice {
            server_index: 0,
            server_name: "local".to_owned(),
            session_id: "session:1".to_owned(),
            label: "work".to_owned(),
        };
        state.set_loading(vec!["office".to_owned(), "lab".to_owned()], false);
        state.apply_server_update(
            vec![local_target.clone()],
            vec![local_session.clone()],
            vec!["local".to_owned()],
            None,
            true,
        );
        let mut buf = Vec::new();
        state.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("[local]") && screen.contains("work") && screen.contains("1 zsh"));
        assert!(screen.contains("Connecting to office, lab…"));

        // 3. One remote server times out while the other is still connecting: banner notifies immediately.
        state.set_loading(vec!["office".to_owned()], false);
        state.apply_server_update(
            vec![local_target.clone()],
            vec![local_session.clone()],
            vec!["local".to_owned()],
            Some("lab: discovery timed out".to_owned()),
            true,
        );
        let mut buf = Vec::new();
        state.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("lab: discovery timed out"));
        assert!(screen.contains("Connecting to office…"));

        // 4. Remaining remote server connects: banner settles to just the timeout warning.
        let office_target = test_target(1, 1, "[office] api / 1 cargo", "session:2", "block:2");
        let office_session = SessionChoice {
            server_index: 1,
            server_name: "office".to_owned(),
            session_id: "session:2".to_owned(),
            label: "api".to_owned(),
        };
        state.set_loading(Vec::new(), false);
        state.apply_server_update(
            vec![local_target.clone(), office_target.clone()],
            vec![local_session.clone(), office_session.clone()],
            vec!["local".to_owned(), "office".to_owned()],
            None,
            false,
        );
        state.finish_loading();
        let mut buf = Vec::new();
        state.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(
            screen.contains("[office]") && screen.contains("api") && screen.contains("1 cargo")
        );
        assert!(screen.contains("lab: discovery timed out"));
        assert!(!screen.contains("Connecting to"));

        // 5. Pending focus survives fast server arriving before the detached target's server.
        state.reset_after_attach(
            Some(FocusTarget {
                server_name: "office".to_owned(),
                session_id: "session:new".to_owned(),
                block_id: "block:new".to_owned(),
            }),
            None,
        );
        state.set_loading(vec!["office".to_owned()], true);
        // local refreshes first — pending_focus for office must stay armed.
        state.apply_server_update(
            vec![local_target.clone()],
            vec![local_session.clone()],
            vec!["local".to_owned()],
            None,
            true,
        );
        // office arrives next with the newly created block — it is focused automatically!
        let new_office_target =
            test_target(1, 1, "[office] fresh / 1 zsh", "session:new", "block:new");
        let new_office_session = SessionChoice {
            server_index: 1,
            server_name: "office".to_owned(),
            session_id: "session:new".to_owned(),
            label: "fresh".to_owned(),
        };
        state.set_loading(Vec::new(), true);
        state.apply_server_update(
            vec![local_target, new_office_target],
            vec![local_session, new_office_session],
            vec!["local".to_owned(), "office".to_owned()],
            None,
            false,
        );
        assert_eq!(
            state.handle_key(KeyCode::Enter, KeyModifiers::NONE),
            Some(Outcome::Selected(Selection::Attach(
                AttachSelection::Existing(1)
            )))
        );

        // 6. When all servers fail on startup, body shows "No reachable servers" instead of Ctrl-N hint.
        let mut empty = PickerState::new(Vec::new(), Vec::new(), Vec::new());
        empty.apply_server_update(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some("remote: discovery timed out".to_owned()),
            false,
        );
        empty.finish_loading();
        let mut buf = Vec::new();
        empty.render(&mut buf, 100, 10, false).unwrap();
        let screen = String::from_utf8(buf).unwrap();
        assert!(screen.contains("No reachable servers"));
        assert!(screen.contains("remote: discovery timed out"));
    }
}
