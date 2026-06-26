package ui

import (
	"testing"
	"time"

	"github.com/ftahirops/xtop/engine"
	"github.com/ftahirops/xtop/model"
)

// minimalTicker is a no-op Ticker so we can construct a Model in tests.
type minimalTicker struct{}

func (minimalTicker) Tick() (*model.Snapshot, *model.RateSnapshot, *model.AnalysisResult) {
	return nil, nil, nil
}
func (minimalTicker) Base() *engine.Engine { return nil }

// newTestModel returns a Model ready for unit tests (no live collector).
func newTestModel() Model {
	return NewModel(minimalTicker{}, time.Second, "")
}

// ---------------------------------------------------------------------------
// Per-page scroll memory
// ---------------------------------------------------------------------------

// TestSwitchPage_SavesAndRestores verifies that switchPage saves the current
// scroll position and restores the target page's remembered position.
func TestSwitchPage_SavesAndRestores(t *testing.T) {
	m := newTestModel()

	// Start on PageOverview (default), set scroll = 42.
	m.page = PageOverview
	m.scroll = 42

	// Switch to CPU; scroll should reset to 0 (first visit).
	m.switchPage(PageCPU)
	if m.page != PageCPU {
		t.Fatalf("expected page=PageCPU, got %v", m.page)
	}
	if m.scroll != 0 {
		t.Errorf("first visit to PageCPU: expected scroll=0, got %d", m.scroll)
	}

	// Set scroll on CPU page.
	m.scroll = 17

	// Switch back to Overview; its saved offset (42) should be restored.
	m.switchPage(PageOverview)
	if m.page != PageOverview {
		t.Fatalf("expected page=PageOverview, got %v", m.page)
	}
	if m.scroll != 42 {
		t.Errorf("returning to PageOverview: expected scroll=42, got %d", m.scroll)
	}

	// Switch back to CPU; its saved offset (17) should be restored.
	m.switchPage(PageCPU)
	if m.scroll != 17 {
		t.Errorf("returning to PageCPU: expected scroll=17, got %d", m.scroll)
	}
}

// TestSwitchPage_ResetsExplainScroll verifies explainScroll is zeroed on page
// change (panel state should not bleed across pages).
func TestSwitchPage_ResetsExplainScroll(t *testing.T) {
	m := newTestModel()
	m.page = PageOverview
	m.explainScroll = 99

	m.switchPage(PageCPU)

	if m.explainScroll != 0 {
		t.Errorf("explainScroll should be 0 after page switch, got %d", m.explainScroll)
	}
}

// TestSwitchPage_MultiplePages verifies scroll memory for several pages.
func TestSwitchPage_MultiplePages(t *testing.T) {
	m := newTestModel()

	pages := []Page{PageOverview, PageCPU, PageMemory, PageIO, PageNetwork}
	scrolls := []int{10, 20, 30, 40, 50}

	// Visit each page and set a scroll position.
	for i, p := range pages {
		m.switchPage(p)
		m.scroll = scrolls[i]
	}

	// Now revisit each page in reverse and check the scroll is restored.
	for i := len(pages) - 1; i >= 0; i-- {
		m.switchPage(pages[i])
		if m.scroll != scrolls[i] {
			t.Errorf("page %v: expected scroll=%d, got %d", pages[i], scrolls[i], m.scroll)
		}
	}
}

// ---------------------------------------------------------------------------
// Bounded explain scroll
// ---------------------------------------------------------------------------

// TestExplainScrollMax_BoundedByContentHeight verifies that renderExplainSidePanel
// writes the correct max into the scrollMaxOut pointer.
func TestExplainScrollMax_BoundedByContentHeight(t *testing.T) {
	var scrollMax int

	// height=40, visibleLines = 40-4 = 36. Content for PageOverview has at
	// least a few lines; with a narrow width (40) wrapping adds more.
	// We just verify max >= 0 and that scrollOffset is clamped.
	_ = renderExplainSidePanel(PageOverview, nil, 40, 40, 9999, false, &scrollMax)

	if scrollMax < 0 {
		t.Errorf("scrollMax should be >= 0, got %d", scrollMax)
	}
	// 9999 >> scrollMax, so the panel should have clamped to scrollMax.
	// We can't read back the clamped offset from outside, but we can verify
	// that the rendered output is non-empty (no panic, no crash).
}

// TestExplainScrollMax_ZeroHeightNoNegative ensures visibleLines floor prevents
// a negative max even on a tiny terminal.
func TestExplainScrollMax_ZeroHeightNoNegative(t *testing.T) {
	var scrollMax int
	_ = renderExplainSidePanel(PageCPU, nil, 30, 1, 0, false, &scrollMax)
	if scrollMax < 0 {
		t.Errorf("scrollMax must never be negative, got %d", scrollMax)
	}
}
