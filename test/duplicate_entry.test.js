"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const os = require("os");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for GHSA-p634-w6r4-rjp2:
// A ZIP archive can declare the same entry name twice. adm-zip kept every entry
// in its entry list but only the last one in its name lookup table, so
// getEntry(name) (table) and extractAllTo() (list) resolved the same name to
// different content. An application validating an entry via getEntry() before
// extracting could approve one file's bytes while another file's bytes were
// written to disk under that name. Such archives are now rejected.

const CENSIG = 0x02014b50;
const LOCSIG = 0x04034b50;
const ENDSIG = 0x06054b50;

const MALICIOUS = "FIRST entry: malicious payload";
const BENIGN = "SECOND entry: benign, validated content";

// Rename the entry called `from` to `to` (same byte length) in both its central
// directory record and its local file header, leaving the data untouched.
function renameEntry(buf, from, to) {
    expect(Buffer.byteLength(from)).to.equal(Buffer.byteLength(to));
    const out = Buffer.from(buf);
    const end = out.length - 22;
    expect(out.readUInt32LE(end)).to.equal(ENDSIG);
    const count = out.readUInt16LE(end + 10);
    let cen = out.readUInt32LE(end + 16);
    for (let i = 0; i < count; i++) {
        expect(out.readUInt32LE(cen)).to.equal(CENSIG);
        const nameLen = out.readUInt16LE(cen + 28);
        const extraLen = out.readUInt16LE(cen + 30);
        const commentLen = out.readUInt16LE(cen + 32);
        const loc = out.readUInt32LE(cen + 42);
        if (out.toString("utf8", cen + 46, cen + 46 + nameLen) === from) {
            out.write(to, cen + 46, "utf8");
            expect(out.readUInt32LE(loc)).to.equal(LOCSIG);
            expect(out.toString("utf8", loc + 30, loc + 30 + nameLen)).to.equal(from);
            out.write(to, loc + 30, "utf8");
            return out;
        }
        cen += 46 + nameLen + extraLen + commentLen;
    }
    throw new Error("entry not found: " + from);
}

// Archive from the advisory PoC: two entries, both named "b.txt", the first
// one carrying different content than the second.
function duplicateNameArchive() {
    const zip = new Zip();
    zip.addFile("a.txt", Buffer.from(MALICIOUS));
    zip.addFile("b.txt", Buffer.from(BENIGN));
    return renameEntry(zip.toBuffer(), "a.txt", "b.txt");
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    let destination;

    beforeEach(() => {
        destination = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-dup-"));
    });

    afterEach(() => {
        rimraf.sync(destination);
    });

    it("the crafted archive really declares the same name twice", () => {
        const buf = duplicateNameArchive();
        const names = [];
        const end = buf.length - 22;
        let cen = buf.readUInt32LE(end + 16);
        for (let i = 0; i < buf.readUInt16LE(end + 10); i++) {
            const nameLen = buf.readUInt16LE(cen + 28);
            names.push(buf.toString("utf8", cen + 46, cen + 46 + nameLen));
            cen += 46 + nameLen + buf.readUInt16LE(cen + 30) + buf.readUInt16LE(cen + 32);
        }
        expect(names).to.deep.equal(["b.txt", "b.txt"]);
    });

    it("getEntries() rejects an archive with duplicate entry names", () => {
        const zip = new Zip(duplicateNameArchive());
        expect(() => zip.getEntries()).to.throw(/Duplicate entry name/);
    });

    it("getEntry() / readFile() reject the duplicated name instead of returning the last entry", () => {
        expect(() => new Zip(duplicateNameArchive()).getEntry("b.txt")).to.throw(/Duplicate entry name/);
        expect(() => new Zip(duplicateNameArchive()).readFile("b.txt")).to.throw(/Duplicate entry name/);
    });

    it("rejects the archive at load time when entries are read eagerly", () => {
        expect(() => new Zip({ input: duplicateNameArchive(), readEntries: true })).to.throw(/Duplicate entry name/);
    });

    it("extractAllTo() rejects the archive and writes nothing to disk", () => {
        const zip = new Zip(duplicateNameArchive());
        expect(() => zip.extractAllTo(destination, true)).to.throw(/Duplicate entry name/);
        expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
        expect(fs.readdirSync(destination)).to.deep.equal([]);
    });

    it("extractAllToAsync() rejects the archive and writes nothing to disk", async () => {
        const zip = new Zip(duplicateNameArchive());
        let error = null;
        try {
            await zip.extractAllToAsync(destination, true);
        } catch (e) {
            error = e;
        }
        expect(error).to.be.an("error");
        expect(error.message).to.match(/Duplicate entry name/);
        expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
        expect(fs.readdirSync(destination)).to.deep.equal([]);
    });

    it("validate-then-extract can no longer approve one entry and extract another", () => {
        // the vulnerable flow: inspect the named entry, then extract everything
        const zip = new Zip(duplicateNameArchive());
        let validated = null;
        expect(() => {
            validated = zip.getEntry("b.txt").getData().toString();
            zip.extractAllTo(destination, true);
        }).to.throw(/Duplicate entry name/);
        expect(validated).to.equal(null);
        expect(fs.existsSync(pth.join(destination, "b.txt"))).to.equal(false);
    });

    it("rejects duplicates that are not adjacent in the central directory", () => {
        const zip = new Zip();
        zip.addFile("a.txt", Buffer.from(MALICIOUS));
        zip.addFile("m.txt", Buffer.from("middle"));
        zip.addFile("z.txt", Buffer.from(BENIGN));
        const buf = renameEntry(zip.toBuffer(), "a.txt", "z.txt");
        expect(() => new Zip(buf).getEntries()).to.throw(/Duplicate entry name/);
    });

    it("rejects duplicate directory entries", () => {
        const zip = new Zip();
        zip.addFile("d1/", Buffer.alloc(0));
        zip.addFile("d2/", Buffer.alloc(0));
        const buf = renameEntry(zip.toBuffer(), "d1/", "d2/");
        expect(() => new Zip(buf).getEntries()).to.throw(/Duplicate entry name/);
    });

    it("still loads archives with distinct names, including Object.prototype member names", () => {
        const names = ["__proto__", "b.txt", "constructor", "hasOwnProperty", "toString", "valueOf"];
        const zip = new Zip();
        names.forEach((name) => zip.addFile(name, Buffer.from("content of " + name)));
        const reopened = new Zip(zip.toBuffer());
        expect(
            reopened
                .getEntries()
                .map((e) => e.entryName)
                .sort()
        ).to.deep.equal(names);
        names.forEach((name) => {
            expect(reopened.readFile(name).toString()).to.equal("content of " + name);
        });
        expect(reopened.getEntry("isDirectory")).to.equal(null);
        expect(reopened.getEntry("getData")).to.equal(null);
    });

    it("an archive with a single entry per name extracts the validated content", () => {
        const zip = new Zip();
        zip.addFile("a.txt", Buffer.from(MALICIOUS));
        zip.addFile("b.txt", Buffer.from(BENIGN));
        const reopened = new Zip(zip.toBuffer());
        expect(reopened.getEntry("b.txt").getData().toString()).to.equal(BENIGN);
        reopened.extractAllTo(destination, true);
        expect(fs.readFileSync(pth.join(destination, "b.txt")).toString()).to.equal(BENIGN);
    });
});
