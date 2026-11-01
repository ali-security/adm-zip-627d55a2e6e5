"use strict";

const { expect } = require("chai");
const pth = require("path");
const fs = require("fs");
const os = require("os");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression tests for CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9):
// sanitize() only proves that the textual entry path stays below the
// extraction root. A symlink that already exists inside the root (e.g. in a
// shared or reused temp / CI directory) was followed by mkdir(), open() and
// chmod(), so an archive entry without any "../" could create or overwrite
// files outside the root. Extraction now refuses to write through any path
// component below the root that is a symlink.

const isWin = process.platform === "win32";
const ORIGINAL = "ORIGINAL victim content";
const PAYLOAD = "attacker controlled payload";

// Create a link, returning false when the platform does not allow it
// (e.g. file symlinks on Windows without the required privilege).
function tryLink(target, path, type) {
    try {
        fs.symlinkSync(pth.resolve(target), path, type);
        return true;
    } catch (e) {
        if (e.code === "EPERM" || e.code === "EACCES" || e.code === "ENOSYS") return false;
        throw e;
    }
}

// Directory links: junctions on Windows (no privilege needed), symlinks elsewhere.
const DIR_LINK = isWin ? "junction" : "dir";

function archive(entries) {
    const zip = new Zip();
    for (const name of Object.keys(entries)) {
        zip.addFile(name, entries[name] === null ? null : Buffer.from(entries[name]));
    }
    return zip.toBuffer();
}

async function rejection(promise) {
    try {
        await promise;
    } catch (e) {
        return e;
    }
    return null;
}

describe("ADM-ZIP - symlink extraction (CVE-2026-76845)", function () {
    // real filesystem work (links, mkdir, rimraf) can stall on Windows runners
    this.timeout(20000);

    let base, dest, outside, victim;

    beforeEach(function () {
        base = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-symlink-"));
        dest = pth.join(base, "dest");
        outside = pth.join(base, "outside");
        victim = pth.join(outside, "victim.txt");
        fs.mkdirSync(dest);
        fs.mkdirSync(outside);
        fs.writeFileSync(victim, ORIGINAL);
        fs.chmodSync(victim, 0o600);
    });

    afterEach(function () {
        rimraf.sync(base);
    });

    // dest/link -> outside
    function plantDirLink(ctx) {
        if (!tryLink(outside, pth.join(dest, "link"), DIR_LINK)) ctx.skip();
    }

    // dest/victim.txt -> outside/victim.txt
    function plantFileLink(ctx) {
        if (!tryLink(victim, pth.join(dest, "victim.txt"), "file")) ctx.skip();
    }

    function expectOutsideUntouched() {
        expect(fs.readdirSync(outside)).to.deep.equal(["victim.txt"]);
        expect(fs.readFileSync(victim, "utf8")).to.equal(ORIGINAL);
        if (!isWin) expect(fs.statSync(victim).mode & 0o777).to.equal(0o600);
    }

    describe("extractAllTo()", function () {
        it("does not create a file through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/pwned.txt": PAYLOAD }));
            expect(() => zip.extractAllTo(dest)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not overwrite a file through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/victim.txt": PAYLOAD }));
            expect(() => zip.extractAllTo(dest, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not overwrite the target of a symlinked file inside the target", function () {
            plantFileLink(this);
            const zip = new Zip(archive({ "victim.txt": PAYLOAD }));
            expect(() => zip.extractAllTo(dest, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not create directories through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/sub/": null }));
            expect(() => zip.extractAllTo(dest, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not write through a symlink nested deeper inside the target", function () {
            fs.mkdirSync(pth.join(dest, "a"));
            if (!tryLink(outside, pth.join(dest, "a", "link"), DIR_LINK)) this.skip();
            const zip = new Zip(archive({ "a/link/pwned.txt": PAYLOAD }));
            expect(() => zip.extractAllTo(dest, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });
    });

    describe("extractEntryTo()", function () {
        it("does not create a single file through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/pwned.txt": PAYLOAD }));
            expect(() => zip.extractEntryTo("link/pwned.txt", dest, true, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not overwrite a single file through a symlinked directory inside the target", function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/victim.txt": PAYLOAD }));
            expect(() => zip.extractEntryTo("link/victim.txt", dest, true, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not overwrite the target of a symlinked file named by outFileName", function () {
            plantFileLink(this);
            const zip = new Zip(archive({ "a.txt": PAYLOAD }));
            expect(() => zip.extractEntryTo("a.txt", dest, false, true, false, "victim.txt")).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not write the children of a folder entry through a symlinked directory", function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/": null, "link/pwned.txt": PAYLOAD, "link/victim.txt": PAYLOAD }));
            expect(() => zip.extractEntryTo("link/", dest, true, true)).to.throw(/file in the way/i);
            expectOutsideUntouched();
        });
    });

    describe("extractAllToAsync()", function () {
        it("does not create a file through a symlinked directory inside the target", async function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/pwned.txt": PAYLOAD }));
            const error = await rejection(zip.extractAllToAsync(dest, false));
            expect(error).to.be.an("error");
            expect(error.message).to.match(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not overwrite a file through a symlinked directory inside the target", async function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/victim.txt": PAYLOAD }));
            const error = await rejection(zip.extractAllToAsync(dest, true));
            expect(error).to.be.an("error");
            expect(error.message).to.match(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not overwrite the target of a symlinked file inside the target", async function () {
            plantFileLink(this);
            const zip = new Zip(archive({ "victim.txt": PAYLOAD }));
            const error = await rejection(zip.extractAllToAsync(dest, true));
            expect(error).to.be.an("error");
            expect(error.message).to.match(/file in the way/i);
            expectOutsideUntouched();
        });

        it("does not create directories through a symlinked directory inside the target", async function () {
            plantDirLink(this);
            const zip = new Zip(archive({ "link/sub/": null }));
            const error = await rejection(zip.extractAllToAsync(dest, true));
            expect(error).to.be.an("error");
            expect(error.message).to.match(/Unable to create folder/);
            expectOutsideUntouched();
        });

        it("reports the error through the callback and stops extracting", function (done) {
            if (!tryLink(outside, pth.join(dest, "link"), DIR_LINK)) return this.skip();
            const zip = new Zip(archive({ "link/pwned.txt": PAYLOAD }));
            zip.extractAllToAsync(dest, true, false, function (err) {
                try {
                    expect(err).to.be.an("error");
                    expect(err.message).to.match(/file in the way/i);
                    expectOutsideUntouched();
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
    });

    describe("legitimate extraction", function () {
        it("still extracts and overwrites regular files next to an unrelated symlink", async function () {
            plantDirLink(this);
            fs.mkdirSync(pth.join(dest, "dir"));
            fs.writeFileSync(pth.join(dest, "dir", "file.txt"), "old");
            fs.writeFileSync(pth.join(dest, "top.txt"), "old");
            const buf = archive({ "dir/": null, "dir/file.txt": "new", "top.txt": "new", "fresh/new.txt": "fresh" });

            new Zip(buf).extractAllTo(dest, true);
            expect(fs.readFileSync(pth.join(dest, "dir", "file.txt"), "utf8")).to.equal("new");
            expect(fs.readFileSync(pth.join(dest, "top.txt"), "utf8")).to.equal("new");
            expect(fs.readFileSync(pth.join(dest, "fresh", "new.txt"), "utf8")).to.equal("fresh");

            fs.writeFileSync(pth.join(dest, "top.txt"), "old");
            expect(new Zip(buf).extractEntryTo("top.txt", dest, true, true)).to.equal(true);
            expect(fs.readFileSync(pth.join(dest, "top.txt"), "utf8")).to.equal("new");

            fs.writeFileSync(pth.join(dest, "top.txt"), "old");
            await new Zip(buf).extractAllToAsync(dest, true);
            expect(fs.readFileSync(pth.join(dest, "top.txt"), "utf8")).to.equal("new");
            expect(fs.readFileSync(pth.join(dest, "dir", "file.txt"), "utf8")).to.equal("new");
            expectOutsideUntouched();
        });

        it("still extracts when the extraction root itself is reached through a symlink", async function () {
            const rootLink = pth.join(base, "rootlink");
            if (!tryLink(dest, rootLink, DIR_LINK)) this.skip();
            const buf = archive({ "a/": null, "a/b.txt": "b", "c.txt": "c" });

            new Zip(buf).extractAllTo(rootLink, true);
            expect(fs.readFileSync(pth.join(dest, "a", "b.txt"), "utf8")).to.equal("b");
            expect(fs.readFileSync(pth.join(dest, "c.txt"), "utf8")).to.equal("c");

            expect(new Zip(buf).extractEntryTo("a/", pth.join(rootLink, "single"), true, true)).to.equal(true);
            expect(fs.readFileSync(pth.join(dest, "single", "a", "b.txt"), "utf8")).to.equal("b");

            await new Zip(buf).extractAllToAsync(pth.join(rootLink, "async"), true);
            expect(fs.readFileSync(pth.join(dest, "async", "a", "b.txt"), "utf8")).to.equal("b");
            expect(fs.readFileSync(pth.join(dest, "async", "c.txt"), "utf8")).to.equal("c");
        });

        it("still extracts with a custom fs that has no lstatSync", function () {
            const customFs = Object.assign({}, fs, { lstatSync: undefined });
            const zip = new Zip(archive({ "a/b.txt": "b" }), { fs: customFs });
            zip.extractAllTo(dest, true);
            expect(fs.readFileSync(pth.join(dest, "a", "b.txt"), "utf8")).to.equal("b");
        });

        it("checks the path with the configured custom fs", function () {
            plantDirLink(this);
            const seen = [];
            const customFs = Object.assign({}, fs, {
                lstatSync: function (p) {
                    seen.push(p);
                    return fs.lstatSync(p);
                }
            });
            const zip = new Zip(archive({ "link/pwned.txt": PAYLOAD }), { fs: customFs });
            expect(() => zip.extractAllTo(dest, true)).to.throw(/file in the way/i);
            expect(seen).to.include(pth.join(dest, "link"));
            expectOutsideUntouched();
        });
    });

    describe("Utils.assertPathSafe()", function () {
        it("rejects symlinked components strictly below the root only", function () {
            plantDirLink(this);
            const utils = new Utils();
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "link"))).to.throw(/file in the way/i);
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "link", "x", "y.txt"))).to.throw(/file in the way/i);
            expect(() => utils.assertPathSafe(dest, pth.join(dest, "real", "y.txt"))).not.to.throw();
            expect(() => utils.assertPathSafe(dest, dest)).not.to.throw();
            // the root itself (and anything above it) is the caller's choice
            expect(() => utils.assertPathSafe(pth.join(dest, "link"), pth.join(dest, "link", "y.txt"))).not.to.throw();
            // paths outside the root are left to sanitize()
            expect(() => utils.assertPathSafe(pth.join(dest, "real"), pth.join(dest, "link", "y.txt"))).not.to.throw();
        });
    });
});
