# encoding: utf-8
#
# Copyright March 2018, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

describe Prawn::Icon::Compatibility do
  describe '#translate' do
    let(:stderr) { StringIO.new }
    subject { described_class.new(key: key) }

    context 'with a non-deprecated key' do
      let(:key) { 'fas-adjust' }

      it 'does not write to STDERR' do
        value = subject.translate(stderr)
        stderr.rewind
        expect(stderr.read).to be_empty
      end

      it 'returns the original key' do
        expect(subject.translate(stderr)).to eq(key)
      end
    end

    context 'with a depreacted FontAwesome key' do
      let(:key) { 'fa-birthday-cake' }
      let(:mapped_key) { 'fas-birthday-cake' }

      it 'writes a deprecation warning to STDERR' do
        subject.translate(stderr)
        stderr.rewind
        errors = stderr.read
        expect(errors).to include('DEPRECATION')
        expect(errors).to include(key)
        expect(errors).to include(mapped_key)
      end

      it 'returns the mapped key' do
        expect(subject.translate(stderr)).to eq(mapped_key)
      end
    end
  end
end
