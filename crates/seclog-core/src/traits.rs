use crate::event::Event;

pub trait EventSource {
    fn next_event(&mut self) -> Option<Event>;
}

pub trait EventWriter {
    fn write_event(&mut self, event: &Event) -> std::io::Result<u64>;
    fn flush(&mut self) -> std::io::Result<()>;
    fn close(&mut self) -> std::io::Result<()>;
}
