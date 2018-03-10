package main

import (
	"flag"
	"fmt"
	"github.com/tobischo/gokeepasslib"
	"os"
)

func main() {
	passPtr := flag.String("pass", "", "Password for the keepass database.")
	flag.Parse()

	if flag.NArg() < 2 {
		flag.PrintDefaults()
		os.Exit(1)
	} else if *passPtr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	fmt.Printf("Diffing %s and %s\n", flag.Arg(0), flag.Arg(1))
	kpdiff(flag.Arg(0), flag.Arg(1), *passPtr)
}

func kpdiff(fp1, fp2, pass string) {
	db1 := openDatabase(fp1, pass)
	db2 := openDatabase(fp2, pass)

	kpdiffGroups(db1.Content.Root.Groups, db2.Content.Root.Groups)
}

func kpdiffGroups(groups1, groups2 []gokeepasslib.Group) {
	if len(groups1) == 0 && len(groups2) == 0 {
		return
	}

	nameToGrp1 := make(map[string]gokeepasslib.Group)
	for _, group := range groups1 {
		nameToGrp1[group.Name] = group
	}

	nameToGrp2 := make(map[string]gokeepasslib.Group)
	for _, group := range groups2 {
		nameToGrp2[group.Name] = group

		if group1, ok := nameToGrp1[group.Name]; ok {
			kpdiffEntries(group.Name, group1.Entries, group.Entries)
			kpdiffGroups(group1.Groups, group.Groups)
		} else {
			kpdiffEntries(group.Name, nil, group.Entries)
			kpdiffGroups(nil, group.Groups)
		}
	}

	// Diff for those groups that only exist in groups1
	for _, group := range groups1 {
		if _, ok := nameToGrp2[group.Name]; !ok {
			kpdiffEntries(group.Name, group.Entries, nil)
			kpdiffGroups(group.Groups, nil)
		}
	}
}

func kpdiffEntries(grpName string, entries1, entries2 []gokeepasslib.Entry) {
	if len(entries1) == 0 && len(entries2) == 0 {
		return
	}

	uuidToEntry1 := make(map[gokeepasslib.UUID]gokeepasslib.Entry)
	for _, entry := range entries1 {
		uuidToEntry1[entry.UUID] = entry
	}

	uuidToEntry2 := make(map[gokeepasslib.UUID]gokeepasslib.Entry)
	for _, entry := range entries2 {

		uuidToEntry2[entry.UUID] = entry

		if entry1, ok := uuidToEntry1[entry.UUID]; ok {
			kpdiffEntry(&entry1, &entry)
		} else {
			kpdiffEntry(nil, &entry)
		}
	}

	// Diff those entries that are only present in entries1
	for _, entry := range entries1 {
		if _, ok := uuidToEntry2[entry.UUID]; !ok {
			kpdiffEntry(&entry, nil)
		}
	}
}

func kpdiffEntry(entry1, entry2 *gokeepasslib.Entry) {
	if entry1 == nil {
		uname2 := entry2.GetContent("UserName")
		fmt.Printf("- %s::%s::%s\n", entry2.GetTitle(), uname2, entry2.GetPassword())
	} else if entry2 == nil {
		uname1 := entry1.GetContent("UserName")
		fmt.Printf("+ %s::%s::%s\n", entry1.GetTitle(), uname1, entry1.GetPassword())
	} else {
		uname1 := entry1.GetContent("UserName")
		uname2 := entry2.GetContent("UserName")
		if entry1.GetTitle() != entry2.GetTitle() ||
			entry1.GetPassword() != entry2.GetPassword() ||
			uname1 != uname2 {
			fmt.Printf("c %s::%s::%s\n", entry1.GetTitle(), uname1, entry1.GetPassword())
			fmt.Printf("  %s::%s::%s\n", entry2.GetTitle(), uname2, entry2.GetPassword())
		}
	}
}

func openDatabase(fp1, pass string) *gokeepasslib.Database {
	file1, err := os.Open(fp1)
	if err != nil {
		fmt.Println("Failed opening", fp1, ":", err)
		os.Exit(1)
	}

	db1 := gokeepasslib.NewDatabase()
	db1.Credentials = gokeepasslib.NewPasswordCredentials(pass)
	err = gokeepasslib.NewDecoder(file1).Decode(db1)
	if err != nil {
		fmt.Println("Failed decoding", fp1, ":", err)
		os.Exit(1)
	}
	err = db1.UnlockProtectedEntries()
	if err != nil {
		fmt.Println("Failed unlocking protected entries", fp1, ":", err)
		os.Exit(1)
	}
	return db1
}
