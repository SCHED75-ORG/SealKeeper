package libraries_test

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sched75/sealkeeper/internal/libraries"
	"github.com/sched75/sealkeeper/internal/storage"
	"github.com/sched75/sealkeeper/internal/storage/storagetest"
)

// ----- Validator ------------------------------------------------------------

func TestValidateDictionaryHappyPath(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("# header\n" +
		"abeille\nbalance\ncerise\n  cerise\nabeille  \n" + // dup ignored both lower-trimmed
		"  Demain\nlivre\n\n")
	r, err := libraries.ValidateDictionary(in)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	// Unique entries: abeille, balance, cerise, demain, livre.
	if r.EntryCount != 5 {
		t.Fatalf("EntryCount = %d, want 5, entries=%v", r.EntryCount, r.Entries)
	}
	// duplicates are reported but the unique entries survive.
	if len(r.FirstErrors) != 2 { // two dup lines
		t.Errorf("FirstErrors = %v, want 2 dup errors", r.FirstErrors)
	}
}

func TestValidateDictionaryRejectsBOM(t *testing.T) {
	t.Parallel()
	in := bytes.NewReader([]byte{0xEF, 0xBB, 0xBF, 'a', 'b', 'c', 'd'})
	if _, err := libraries.ValidateDictionary(in); !errors.Is(err, libraries.ErrInvalidEncoding) {
		t.Fatalf("err = %v, want ErrInvalidEncoding", err)
	}
}

func TestValidateDictionaryRejectsBadLines(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		"ab\n" + // too short
			"toolongword12\n" + // 13 > 12 max
			"sym!bols\n" + // non-letter
			"alpha\n" + // good
			"  \n",
	)
	r, err := libraries.ValidateDictionary(in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r.EntryCount != 1 || r.Entries[0] != "alpha" {
		t.Errorf("entries = %v, want only [alpha]", r.Entries)
	}
	if len(r.FirstErrors) != 3 {
		t.Errorf("FirstErrors = %v, want 3", r.FirstErrors)
	}
}

func TestValidateDictionaryEmpty(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("# just comments\n\n#\n")
	if _, err := libraries.ValidateDictionary(in); !errors.Is(err, libraries.ErrEmptyFile) {
		t.Fatalf("err = %v, want ErrEmptyFile", err)
	}
}

func TestValidateCorpusWordCount(t *testing.T) {
	t.Parallel()
	in := strings.NewReader(
		"one two\n" + // 2 words — too short
			"alpha bravo charlie\n" + // 3 — good
			strings.Repeat("word ", 26) + "\n" + // 26 — too long
			"\n",
	)
	r, err := libraries.ValidateCorpus(in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r.EntryCount != 1 {
		t.Errorf("EntryCount = %d, want 1", r.EntryCount)
	}
	if len(r.FirstErrors) != 2 {
		t.Errorf("FirstErrors = %v, want 2", r.FirstErrors)
	}
}

func TestValidateCorpusKeepsDiacriticsAndDigits(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("Je pense donc je suis 1637\n" +
		"Étant donné que l'esprit est l'enfant du cœur\n")
	r, err := libraries.ValidateCorpus(in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if r.EntryCount != 2 {
		t.Fatalf("EntryCount = %d", r.EntryCount)
	}
	if !strings.Contains(r.Entries[0], "1637") {
		t.Errorf("digits dropped: %q", r.Entries[0])
	}
}

func TestValidateUnknownKind(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("anything")
	if _, err := libraries.Validate(libraries.Kind("songs"), in); !errors.Is(err, libraries.ErrUnknownKind) {
		t.Fatalf("err = %v, want ErrUnknownKind", err)
	}
}

func TestValidateDictionaryWarnsBelowRecommendedSize(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("alpha\nbravo\ncharlie\ndelta\n")
	r, err := libraries.ValidateDictionary(in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(r.Warnings) == 0 {
		t.Fatal("expected a warning about size < recommended")
	}
}

// ----- Repo / Upload --------------------------------------------------------

func newRepo(t *testing.T) *libraries.Repo {
	t.Helper()
	dir := t.TempDir()
	dbDSN := storagetest.DSN(t)
	storeDir := filepath.Join(dir, "store")
	ctx, cancel := context.WithTimeout(context.Background(), storagetest.SetupTimeout)
	defer cancel()
	s, err := storage.Open(ctx, storage.Options{DSN: dbDSN})
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	if err := s.MigrateUp(ctx); err != nil {
		t.Fatalf("MigrateUp: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	repo, err := libraries.NewRepo(s.DB(), storeDir)
	if err != nil {
		t.Fatalf("NewRepo: %v", err)
	}
	return repo
}

func TestUploadAndReadBack(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()

	body := "alpha\nbravo\ncharlie\ndelta\necho\nfoxtrot\n"
	lib, report, err := repo.Upload(ctx, libraries.UploadInputs{
		Name:     "test-dict",
		Kind:     libraries.KindDictionary,
		Language: "FR",
		Content:  strings.NewReader(body),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if lib.EntryCount != 6 {
		t.Errorf("EntryCount = %d, want 6", lib.EntryCount)
	}
	if lib.Language != "fr" {
		t.Errorf("Language = %q, want lowercased", lib.Language)
	}
	if !strings.HasSuffix(lib.FilePath, ".txt") {
		t.Errorf("FilePath = %q, want sha.txt", lib.FilePath)
	}
	if len(report.Warnings) == 0 {
		t.Error("expected size warning")
	}

	// Sample reads the file back.
	_, sample, err := repo.Sample(ctx, lib.ID, 3)
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if len(sample) != 3 || sample[0] != "alpha" {
		t.Errorf("Sample = %v", sample)
	}

	_, rc, err := repo.Open(ctx, lib.ID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
}

func TestUploadDuplicateHash(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()
	body := "alpha\nbravo\ncharlie\n"
	if _, _, err := repo.Upload(ctx, libraries.UploadInputs{
		Name: "first", Kind: libraries.KindDictionary, Language: "fr",
		Content: strings.NewReader(body),
	}); err != nil {
		t.Fatalf("first Upload: %v", err)
	}
	_, _, err := repo.Upload(ctx, libraries.UploadInputs{
		Name: "duplicate", Kind: libraries.KindDictionary, Language: "fr",
		Content: strings.NewReader(body),
	})
	if !errors.Is(err, libraries.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestUploadRejectsInvalidContent(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()
	_, _, err := repo.Upload(ctx, libraries.UploadInputs{
		Name: "bad", Kind: libraries.KindDictionary, Language: "fr",
		Content: strings.NewReader("# only comments\n"),
	})
	if !errors.Is(err, libraries.ErrEmptyFile) {
		t.Fatalf("err = %v, want ErrEmptyFile", err)
	}
}

func TestDeleteRemovesFileAndRow(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()
	lib, _, err := repo.Upload(ctx, libraries.UploadInputs{
		Name: "delete-me", Kind: libraries.KindDictionary, Language: "fr",
		Content: strings.NewReader("alpha\nbravo\ncharlie\n"),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := repo.Delete(ctx, lib.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.Get(ctx, lib.ID); !errors.Is(err, libraries.ErrNotFound) {
		t.Fatalf("post-delete Get err = %v, want ErrNotFound", err)
	}
}

func TestDeleteRefusesSystemLibrary(t *testing.T) {
	t.Parallel()
	repo := newRepo(t)
	ctx := context.Background()
	lib, _, err := repo.Upload(ctx, libraries.UploadInputs{
		Name: "system", Kind: libraries.KindDictionary, Language: "fr",
		System: true, Content: strings.NewReader("alpha\nbravo\ncharlie\n"),
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if err := repo.Delete(ctx, lib.ID); !errors.Is(err, libraries.ErrSystemReadOnly) {
		t.Fatalf("err = %v, want ErrSystemReadOnly", err)
	}
}
