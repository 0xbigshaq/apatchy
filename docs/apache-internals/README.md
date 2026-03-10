# Apache Internals: A Practical Guide

**From Zero to Fuzzing**

This guide is designed for developers with C and Linux experience who want to understand Apache HTTP Server's internal architecture. By the end, you'll understand enough to build a fuzzing harness that exercises Apache's request processing pipeline.

---

## Table of Contents

### Part 0x01: Foundations

1. **[Introduction to Apache Architecture](01-introduction.md)**
   - High-level overview and layer stack
   - Key abstractions ({httpd}`request_rec`, {httpd}`conn_rec`, {httpd}`server_rec`)
   - Source code organization
   - Core data structures

2. **[APR - Apache Portable Runtime](02-apr.md)**
   - Why APR exists (portability layer between Apache and the OS)
   - Strings, arrays, tables, hash tables
   - File and network I/O abstractions
   - How APR relates to fuzzing (`--with-included-apr`)

3. **[Memory Management and Pools](03-memory-pools.md)**
   - Why pools instead of `malloc`/`free`
   - Pool hierarchy (pconf → connection → request)
   - Pool API, cleanups, and subpools for loops
   - Pool debugging with ASan (`--enable-pool-debug=yes`)

### Part 0x02: Core Systems

4. **[The Configuration System](04-configuration.md)**
   - Configuration contexts (`<Directory>`, `<Location>`, `.htaccess`)
   - Directive types and the command table
   - Config creators, mergers, and the per-request merge flow
   - Module config vectors and runtime access

5. **[MPM - Multi-Processing Modules](05-mpm.md)**
   - Prefork, Worker, Event MPMs and their trade-offs
   - Connection handling lifecycle
   - Scoreboard and worker status tracking
   - Thread safety considerations for modules

6. **[The Hook System](06-hooks.md)**
   - What hooks are and how they work
   - Hook ordering constants and predecessor/successor lists
   - Return values ({httpd}`OK`, {httpd}`DECLINED`, {httpd}`DONE`, `HTTP_*`)
   - Major request and connection hooks
   - Hook infrastructure: macros, {httpd}`ap_setup_prelinked_modules`, sorting

### Part 0x03: I/O Architecture

7. **[Filters and Bucket Brigades](07-filters-buckets.md)**
   - Bucket types: data (heap, pool, transient, immortal), I/O (file, pipe, socket), metadata (EOS, FLUSH)
   - The {httpd}`apr_bucket_type_t` vtable and zero-copy {httpd}`setaside` morphing
   - Brigades as linked rings of buckets
   - Input vs output filters and the filter type hierarchy
   - Common patterns: pass-through, accumulating, streaming

8. **[Request Processing Pipeline](08-request-pipeline.md)**
   - Complete lifecycle from connection accept to pool cleanup
   - Each processing phase in detail (with source file references)
   - Directory walk and per-request config merge
   - Internal redirects, subrequests, and error handling
   - Fuzzing entry points and what each phase exercises

### Part 0x04: Practical Application

9. **[Module Anatomy](09-module-anatomy.md)**
   - The {httpd}`module` struct and {httpd}`STANDARD20_MODULE_STUFF`
   - Complete annotated module template
   - Configuration directives (`AP_INIT_*` macros, {httpd}`ACCESS_CONF` vs {httpd}`RSRC_CONF`)
   - Adding filters and custom hooks to a module
   - Lifecycle hooks (`child_init`, `post_config`)
   - How to read a module's source for fuzzing targets

<!-- Phase 3: For building/linking and fuzzing harness architecture, see the [architecture](../architecture/harness-design.md) section. -->

---

## How to Read This Guide

**If you're new to Apache:**
Start from Chapter 1 and read sequentially. Each chapter builds on the previous ones.

**If you want to write a module:**
Focus on Chapters 1, 3, 4, 6, 7, and 9. These cover the essential concepts for module development.

**If you want to understand the fuzzing harness:**
Read Chapters 5-8 first for context, then the harness design document (coming soon).

**If you need a quick reference:**
Each chapter is self-contained with code examples. Jump to the topic you need.

---

## Prerequisites

- Solid C programming knowledge
- Linux development experience
- Familiarity with:
  - Makefiles
  - Shared libraries
  - Basic networking concepts

No prior Apache knowledge required.

---

## Further Resources

- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/2.4/)
- [APR Documentation](https://apr.apache.org/docs/apr/trunk/)
- [Apache Module Development Guide](https://httpd.apache.org/docs/2.4/developer/modguide.html)
- Apache source code: `include/*.h` for API documentation
