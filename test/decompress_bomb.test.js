"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const pth = require("path");
const fs = require("fs");
const os = require("os");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const crc32 = require("../util").crc32;

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid unless `crc` is given) payload.
function craftBomb(declaredSize, method, content, crc) {
    const name = Buffer.from("a");
    crc = crc || 0; // deliberately wrong by default: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// Record the largest Buffer allocation requested while `fn` runs. Requests above
// ALLOC_LIMIT are refused instead of served, so a build that still sizes the output
// buffer from the declared size fails the assertion rather than committing
// gigabytes on the test machine.
const ALLOC_LIMIT = 64 * 1024 * 1024;
function trackAllocations(fn) {
    const names = ["alloc", "allocUnsafe", "allocUnsafeSlow"];
    const originals = names.map((name) => Buffer[name]);
    const seen = { largest: 0, error: null, result: undefined };
    names.forEach((name, i) => {
        Buffer[name] = function (size) {
            if (size > seen.largest) seen.largest = size;
            if (size > ALLOC_LIMIT) throw new RangeError("refused to allocate " + size + " bytes");
            return originals[i].apply(Buffer, arguments);
        };
    });
    try {
        seen.result = fn();
    } catch (e) {
        seen.error = e;
    } finally {
        names.forEach((name, i) => {
            Buffer[name] = originals[i];
        });
    }
    return seen;
}

describe("declared size does not drive allocation in any read path - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB declared, a few KB actually present
    const text = Buffer.from("hello world ".repeat(100));
    const tmpRoot = pth.join(os.tmpdir(), "adm-zip-cve-2026-39244-" + process.pid);

    after(() => rimraf.sync(tmpRoot));

    const expectBounded = (seen) => {
        expect(seen.largest, "allocation must be bound by the archive data, not the declared size").to.be.at.most(ALLOC_LIMIT);
        if (seen.error) throw seen.error;
    };
    // runs an async reader, checking the synchronous part for the eager allocation
    // and the callback for the real content
    const asyncCheck = (done, start, check) => {
        let finished = false;
        const seen = trackAllocations(() =>
            start(function () {
                if (finished) return;
                finished = true;
                try {
                    check.apply(null, arguments);
                    done();
                } catch (e) {
                    done(e);
                }
            })
        );
        expectBounded(seen);
    };

    [
        { label: "STORED", method: 0 /* STORED */, content: text },
        { label: "DEFLATED", method: 8 /* DEFLATED */, content: zlib.deflateRawSync(text) }
    ].forEach((variant) => {
        // the crc matches the real content: the only lie is the declared uncompressed size
        const bomb = () => new Zip(craftBomb(DECLARED, variant.method, variant.content, crc32(text)));
        const outDir = (name) => pth.join(tmpRoot, variant.label + "-" + name);

        it(`${variant.label}: entry.getData`, () => {
            const zip = bomb();
            const seen = trackAllocations(() => zip.getEntries()[0].getData());
            expectBounded(seen);
            expect(seen.result.equals(text)).to.equal(true);
        });

        it(`${variant.label}: readFile`, () => {
            const zip = bomb();
            const seen = trackAllocations(() => zip.readFile("a"));
            expectBounded(seen);
            expect(seen.result.equals(text)).to.equal(true);
        });

        it(`${variant.label}: readAsText`, () => {
            const zip = bomb();
            const seen = trackAllocations(() => zip.readAsText("a"));
            expectBounded(seen);
            expect(seen.result).to.equal(text.toString());
        });

        it(`${variant.label}: test`, () => {
            const zip = bomb();
            const seen = trackAllocations(() => zip.test());
            expectBounded(seen);
            expect(seen.result).to.equal(true);
        });

        it(`${variant.label}: extractEntryTo`, () => {
            const zip = bomb();
            const target = outDir("extractEntryTo");
            const seen = trackAllocations(() => zip.extractEntryTo("a", target, false, true));
            expectBounded(seen);
            expect(fs.readFileSync(pth.join(target, "a")).equals(text)).to.equal(true);
        });

        it(`${variant.label}: extractAllTo`, () => {
            const zip = bomb();
            const target = outDir("extractAllTo");
            const seen = trackAllocations(() => zip.extractAllTo(target, true));
            expectBounded(seen);
            expect(fs.readFileSync(pth.join(target, "a")).equals(text)).to.equal(true);
        });

        it(`${variant.label}: entry.getDataAsync`, (done) => {
            const zip = bomb();
            asyncCheck(
                done,
                (cb) => zip.getEntries()[0].getDataAsync(cb),
                (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data.equals(text)).to.equal(true);
                }
            );
        });

        it(`${variant.label}: readFileAsync`, (done) => {
            const zip = bomb();
            asyncCheck(
                done,
                (cb) => zip.readFileAsync("a", cb),
                (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data.equals(text)).to.equal(true);
                }
            );
        });

        it(`${variant.label}: readAsTextAsync`, (done) => {
            const zip = bomb();
            asyncCheck(
                done,
                (cb) => zip.readAsTextAsync("a", cb),
                (data, err) => {
                    expect(err).to.equal(undefined);
                    expect(data).to.equal(text.toString());
                }
            );
        });

        it(`${variant.label}: extractAllToAsync`, (done) => {
            const zip = bomb();
            const target = outDir("extractAllToAsync");
            asyncCheck(
                done,
                (cb) => zip.extractAllToAsync(target, true, false, cb),
                (err) => {
                    expect(err).to.equal(undefined);
                    expect(fs.readFileSync(pth.join(target, "a")).equals(text)).to.equal(true);
                }
            );
        });
    });
});
