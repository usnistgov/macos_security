# encoding: utf-8
#
# Copyright September 2016, Jesse Doyle. All rights reserved.
#
# This is free software. Please see the LICENSE and COPYING files for details.

describe Prawn::Icon::Errors::IconKeyEmpty do
  let(:pdf) { create_pdf }

  it 'is a StandardError' do
    expect(subject).to be_a(StandardError)
  end

  it 'is thrown on a missing icon key' do
    expect { pdf.icon('') }.to raise_error(described_class)
  end
end
