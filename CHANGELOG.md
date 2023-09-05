# Changelog

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v0.8.0 - 2023-09-01

- Change to Mutex to allow thread safety since RefCell isn't.

## v0.6.0 - 2023-08-29

- Add soteria-rs to protect internals from side channels. No API chanages.

## v0.7.0 - 2023-08-31

- Change Rc to Arc for thread safety

## v0.6.0 - 2023-08-29

- Add RAM protection for side-channels to secret shares

## v0.5.0 - 2023-07-26

- Fix binary serialization error

## v0.4.0 - 2023

- Update with_secret to handle adding and removing participants

## v0.3.0 - 2023-05-11

- Update to vsss 3.0 
- Change Participant to be trait to reduce code duplication

## v0.2.8 - 2023-02-27

- Update to vsss 2.7 which allows splitting zero secrets

## v0.2.7 - 2023-02-27

- Update dependencies

## v0.2.5 - 2023-02-24

- derive Default for Logger
- Fixed participant serialization

## v0.2.4 - 2023-02-24

- derive traits for Logger

## v0.2.3 - 2023-02-23

- derive Clone for Participants

## v0.2.2 - 2023-02-23

- Dependency update

## v0.2.1 - 2023-01-24

- Add Debug Trait
- Add typed Participants
- Add IoError

## v0.2.0 - 2023-01-20

- Update to have secret and refresh participants
- Add loggers
- Continue protocol as long as above threshold

## v0.1.0 - 2022-12

- Initial release.
